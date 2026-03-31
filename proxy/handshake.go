package proxy

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"mtproxy/config"
	"mtproxy/crypto"
	"mtproxy/proto"
)

// ── Replay 防护 ───────────────────────────────────────────────────────────────

type replayCache struct {
	mu     sync.Mutex
	cache  map[string]bool
	order  []string
	maxLen int
}

func NewReplayCache(maxLen int) *replayCache {
	return &replayCache{cache: make(map[string]bool), maxLen: maxLen}
}

func (rc *replayCache) Has(key []byte) bool {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return rc.cache[string(key)]
}

func (rc *replayCache) Add(key []byte) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if rc.maxLen > 0 && len(rc.order) >= rc.maxLen {
		oldest := rc.order[0]
		rc.order = rc.order[1:]
		delete(rc.cache, oldest)
	}
	k := string(key)
	rc.cache[k] = true
	rc.order = append(rc.order, k)
}

var UsedHandshakes *replayCache
var ClientIPs *replayCache

// ── 握手结果 ──────────────────────────────────────────────────────────────────

type HandshakeResult struct {
	Reader    proto.StreamReader
	Writer    proto.StreamWriter
	ProtoTag  []byte
	SecretHex string
	DcIdx     int
	EncKeyIV  []byte
	Peer      net.Addr
}

// ── TLS 伪装握手 ──────────────────────────────────────────────────────────────

func handleFakeTLSHandshake(handshake []byte, reader proto.StreamReader, writer proto.StreamWriter,
	peer net.Addr, cfg *config.Config) (proto.StreamReader, proto.StreamWriter, error) {

	const (
		digestLen     = 32
		digestHalfLen = 16
		digestPos     = 11
	)

	sessionIDLenPos := digestPos + digestLen
	sessionIDPos := sessionIDLenPos + 1

	tlsVers := []byte{0x03, 0x03}
	tlsCiphersuite := []byte{0x13, 0x01}
	tlsChangeCipher := []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01}
	tlsAppHTTP2Hdr := []byte{0x17, 0x03, 0x03}

	tlsExtensions := []byte{0x00, 0x2e, 0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20}
	tlsExtensions = append(tlsExtensions, crypto.GlobalRand.GenX25519PublicKey()...)
	tlsExtensions = append(tlsExtensions, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04)

	digest := handshake[digestPos : digestPos+digestLen]

	if UsedHandshakes.Has(digest[:digestHalfLen]) {
		return nil, nil, fmt.Errorf("duplicate handshake")
	}

	sessIDLen := int(handshake[sessionIDLenPos])
	sessID := handshake[sessionIDPos : sessionIDPos+sessIDLen]

	Dbgf(cfg, "[DEBUG] TLS handshake: handshake len=%d digestPos=%d digest=%x\n",
		len(handshake), digestPos, digest[:8])

	for _, secret := range cfg.Secrets {
		msg := make([]byte, len(handshake))
		copy(msg, handshake)
		for i := digestPos; i < digestPos+digestLen; i++ {
			msg[i] = 0
		}

		mac := hmac.New(sha256.New, secret)
		mac.Write(msg)
		computedDigest := mac.Sum(nil)

		xored := make([]byte, digestLen)
		for i := range xored {
			xored[i] = digest[i] ^ computedDigest[i]
		}

		Dbgf(cfg, "[DEBUG] TLS xored[:4]=%x (want 00000000)\n", xored[:4])

		// 检查前 28 字节是否为 0
		allZero := true
		for _, b := range xored[:digestLen-4] {
			if b != 0 {
				allZero = false
				break
			}
		}
		if !allZero {
			continue
		}

		timestamp := int64(binary.LittleEndian.Uint32(xored[digestLen-4:]))
		now := time.Now().Unix()
		skew := now - timestamp
		const timeSkewMin = -20 * 60
		const timeSkewMax = 10 * 60
		clientTimeOK := skew > timeSkewMin && skew < timeSkewMax
		clientTimeSmall := timestamp < 60*60*24*1000
		Dbgf(cfg, "[DEBUG] TLS timestamp=%d now=%d skew=%d ok=%v\n", timestamp, now, skew, clientTimeOK)
		if !clientTimeOK && !cfg.IgnoreTimeSkew && !clientTimeSmall {
			continue
		}

		fakeCertLen := rand.Intn(4096-1024) + 1024
		httpData := crypto.GlobalRand.Bytes(fakeCertLen)

		srvHello := append(tlsVers, make([]byte, digestLen)...)
		srvHello = append(srvHello, byte(sessIDLen))
		srvHello = append(srvHello, sessID...)
		srvHello = append(srvHello, tlsCiphersuite...)
		srvHello = append(srvHello, 0x00)
		srvHello = append(srvHello, tlsExtensions...)

		srvHelloInnerLen := make([]byte, 3)
		srvHelloInnerLen[0] = byte(len(srvHello) >> 16)
		srvHelloInnerLen[1] = byte(len(srvHello) >> 8)
		srvHelloInnerLen[2] = byte(len(srvHello))
		outerLen := len(srvHello) + 4
		helloPkt := []byte{0x16, 0x03, 0x03, byte(outerLen >> 8), byte(outerLen)}
		helloPkt = append(helloPkt, 0x02)
		helloPkt = append(helloPkt, srvHelloInnerLen...)
		helloPkt = append(helloPkt, srvHello...)
		helloPkt = append(helloPkt, tlsChangeCipher...)
		helloPkt = append(helloPkt, tlsAppHTTP2Hdr...)
		helloPkt = append(helloPkt, byte(len(httpData)>>8), byte(len(httpData)))
		helloPkt = append(helloPkt, httpData...)

		mac2 := hmac.New(sha256.New, secret)
		mac2.Write(digest)
		mac2.Write(helloPkt)
		computedDigest2 := mac2.Sum(nil)
		copy(helloPkt[digestPos:], computedDigest2)

		if err := writer.Write(helloPkt, nil); err != nil {
			return nil, nil, err
		}

		if cfg.ReplayCheckLen > 0 {
			UsedHandshakes.Add(digest[:digestHalfLen])
		}

		return &proto.FakeTLSReader{Upstream: reader}, &proto.FakeTLSWriter{Upstream: writer}, nil
	}

	return nil, nil, fmt.Errorf("no matching secret")
}

// ── 主握手处理 ────────────────────────────────────────────────────────────────

func HandleHandshake(conn net.Conn, cfg *config.Config) (*HandshakeResult, []byte, error) {
	tlsStartBytes := []byte{0x16, 0x03, 0x01}

	reader := &proto.TCPReader{Conn: conn}
	writer := &proto.TCPWriter{Conn: conn}

	// proxy protocol 解析
	var peerAddr net.Addr = conn.RemoteAddr()
	if cfg.ProxyProtocol {
		var err2 error
		peerAddr, err2 = proto.HandleProxyProtocol(reader, peerAddr)
		if err2 != nil || peerAddr == nil {
			return nil, nil, fmt.Errorf("bad proxy protocol header: %v", err2)
		}
	}

	var handshake []byte
	isTLS := true

	for _, expected := range tlsStartBytes {
		b, err := reader.ReadExactly(1)
		if err != nil {
			return nil, nil, err
		}
		handshake = append(handshake, b...)
		if b[0] != expected {
			isTLS = false
			break
		}
	}

	if isTLS {
		lenBytes, err := reader.ReadExactly(2)
		if err != nil {
			return nil, nil, err
		}
		handshake = append(handshake, lenBytes...)
		tlsLen := int(binary.BigEndian.Uint16(lenBytes))
		if tlsLen < 512 {
			isTLS = false
		} else {
			body, err := reader.ReadExactly(tlsLen)
			if err != nil {
				return nil, nil, err
			}
			handshake = append(handshake, body...)
		}
	}

	var sr proto.StreamReader = reader
	var sw proto.StreamWriter = writer

	if isTLS {
		newReader, newWriter, err := handleFakeTLSHandshake(handshake, sr, sw, conn.RemoteAddr(), cfg)
		if err != nil {
			return nil, handshake, fmt.Errorf("tls handshake failed: %w", err)
		}
		sr = newReader
		sw = newWriter
		hs, err := sr.ReadExactly(config.HandshakeLen)
		if err != nil {
			return nil, nil, err
		}
		handshake = hs
	} else {
		if !cfg.Modes.Classic && !cfg.Modes.Secure {
			return nil, handshake, fmt.Errorf("classic/secure modes disabled")
		}
		rest, err := sr.ReadExactly(config.HandshakeLen - len(handshake))
		if err != nil {
			return nil, nil, err
		}
		handshake = append(handshake, rest...)
	}

	decPrekeyAndIV := handshake[config.SkipLen : config.SkipLen+config.PrekeyLen+config.IVLen]
	decPrekey := decPrekeyAndIV[:config.PrekeyLen]
	decIV := decPrekeyAndIV[config.PrekeyLen:]

	encPrekeyAndIV := make([]byte, len(decPrekeyAndIV))
	copy(encPrekeyAndIV, decPrekeyAndIV)
	ReverseBytes(encPrekeyAndIV)
	encPrekey := encPrekeyAndIV[:config.PrekeyLen]
	encIV := encPrekeyAndIV[config.PrekeyLen:]

	if cfg.ReplayCheckLen > 0 && UsedHandshakes.Has(decPrekeyAndIV) {
		return nil, handshake, fmt.Errorf("replay detected")
	}

	for _, secret := range cfg.Secrets {
		decInput := make([]byte, len(decPrekey)+len(secret))
		copy(decInput, decPrekey)
		copy(decInput[len(decPrekey):], secret)
		decKeyRaw := sha256.Sum256(decInput)
		decKey := decKeyRaw[:]
		decIV16 := make([]byte, 16)
		copy(decIV16, decIV)

		encInput := make([]byte, len(encPrekey)+len(secret))
		copy(encInput, encPrekey)
		copy(encInput[len(encPrekey):], secret)
		encKeyRaw := sha256.Sum256(encInput)
		encKey := encKeyRaw[:]
		encIV16 := make([]byte, 16)
		copy(encIV16, encIV)

		streamDecryptorTmp := crypto.NewAESCTR(decKey, crypto.Uint128FromBytes(decIV16))
		decrypted := streamDecryptorTmp.Decrypt(handshake)

		protoTag := decrypted[config.ProtoTagPos : config.ProtoTagPos+4]

		isAbridged := bytes.Equal(protoTag, proto.ProtoTagAbridged)
		isIntermediate := bytes.Equal(protoTag, proto.ProtoTagIntermediate)
		isSecure := bytes.Equal(protoTag, proto.ProtoTagSecure)

		if !isAbridged && !isIntermediate && !isSecure {
			continue
		}

		if isSecure {
			if isTLS && !cfg.Modes.TLS {
				continue
			}
			if !isTLS && !cfg.Modes.Secure {
				continue
			}
		} else {
			if !cfg.Modes.Classic {
				continue
			}
		}

		dcIdx := int(int16(binary.LittleEndian.Uint16(decrypted[config.DCIdxPos : config.DCIdxPos+2])))

		if cfg.ReplayCheckLen > 0 {
			UsedHandshakes.Add(decPrekeyAndIV)
		}

		encIV16b := make([]byte, 16)
		copy(encIV16b, encIV)
		streamEncryptor := crypto.NewAESCTR(encKey, crypto.Uint128FromBytes(encIV16b))
		cryptoR := &proto.CryptoReader{Upstream: sr, Decryptor: streamDecryptorTmp, BlockSize: 1}
		cryptoW := &proto.CryptoWriter{Upstream: sw, Encryptor: streamEncryptor, BlockSize: 1}

		return &HandshakeResult{
			Reader:    cryptoR,
			Writer:    cryptoW,
			ProtoTag:  protoTag,
			SecretHex: fmt.Sprintf("%x", secret),
			DcIdx:     dcIdx,
			EncKeyIV:  append(encKey, encIV...),
			Peer:      conn.RemoteAddr(),
		}, nil, nil
	}

	return nil, handshake, fmt.Errorf("no matching secret")
}

func ReverseBytes(b []byte) {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
}
