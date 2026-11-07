package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime/debug"
	"time"

	"mtproxy/config"
	"mtproxy/proto"
	"mtproxy/stats"
)

func pipeReaderToWriter(rd proto.StreamReader, wr proto.StreamWriter, secretHex string, bufSize int, upstream bool) error {
	stat := stats.GlobalStats.GetOrCreateSecretStat(secretHex)
	for {
		data, extra, readErr := rd.Read(bufSize)
		if extra == nil || !extra["SKIP_SEND"] {
			if len(data) > 0 {
				if err := wr.Write(data, extra); err != nil {
					return err
				}
				if upstream {
					stat.AddOctetsFromClt(int64(len(data)))
					stat.AddMsgsFromClt(1)
				} else {
					stat.AddOctetsToClt(int64(len(data)))
					stat.AddMsgsToClt(1)
				}
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return wr.WriteEOF()
			}
			return readErr
		}
		if len(data) == 0 && (extra == nil || !extra["SKIP_SEND"]) {
			return io.ErrNoProgress
		}
	}
}

// Unauthenticated connections have a fixed, bounded lifetime, even if peers
// continue sending bytes. Both forwarding goroutines finish before returning.
func HandleBadClient(conn net.Conn, handshake []byte, cfg *config.Config) {
	if !cfg.Mask || len(handshake) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.ClientHandshakeTimeout)*time.Second)
	defer cancel()
	dialer := net.Dialer{Timeout: time.Duration(cfg.TGConnectTimeout) * time.Second}
	mask, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(cfg.MaskHost, fmt.Sprint(cfg.MaskPort)))
	if err != nil {
		return
	}
	defer mask.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close(); mask.Close() })
	defer stop()
	if err := (&proto.TCPWriter{Conn: mask}).Write(handshake, nil); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(mask, conn)
		if tc, ok := mask.(interface{ CloseWrite() error }); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		io.Copy(conn, mask)
		if tc, ok := conn.(interface{ CloseWrite() error }); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	// The context closes both connections at the lifetime limit, even if a
	// peer half-closes and the other peer never sends its final response.
	<-done
	<-done
}

func HandleClient(conn net.Conn, cfg *config.Config) {
	defer conn.Close()
	SetKeepalive(conn, cfg.ClientKeepalive)
	stats.GlobalStats.IncConnectsAll()
	conn.SetDeadline(time.Now().Add(time.Duration(cfg.ClientHandshakeTimeout) * time.Second))
	hs, handshake, err := HandleHandshake(conn, cfg)
	conn.SetDeadline(time.Time{})
	if err != nil {
		stats.GlobalStats.IncConnectsBad()
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			stats.GlobalStats.IncHandshakeTimeouts()
		}
		Debugf(cfg, "handshake failed from %s: %v\n", conn.RemoteAddr(), err)
		HandleBadClient(conn, handshake, cfg)
		return
	}
	stat := stats.GlobalStats.GetOrCreateSecretStat(hs.SecretHex)
	stat.IncConnects()
	stat.AddCurrConnects(1)
	defer stat.AddCurrConnects(-1)
	var tgReader proto.StreamReader
	var tgWriter proto.StreamWriter
	direct := !cfg.UseMiddleProxy
	if direct {
		var key []byte
		if cfg.FastMode {
			key = hs.EncKeyIV
		}
		tgReader, tgWriter, err = DoDirectHandshake(hs.ProtoTag, hs.DcIdx, key, cfg)
	} else {
		addr, ok := hs.Peer.(*net.TCPAddr)
		if !ok {
			Warnf("middle proxy requires a TCP peer or PROXY protocol address\n")
			return
		}
		tgReader, tgWriter, err = DoMiddleproxyHandshake(hs.ProtoTag, hs.DcIdx, addr.IP.String(), addr.Port, cfg)
	}
	if err != nil {
		Debugf(cfg, "TG connect failed: %v\n", err)
		return
	}
	defer tgWriter.Abort()
	// The handshake used the raw connection deadline. From here onward the
	// stream's TCP adapters use per-I/O idle deadlines instead.
	idleClient := &proto.IdleConn{Conn: conn, ReadTimeout: time.Duration(cfg.TGReadTimeout) * time.Second, WriteTimeout: time.Duration(cfg.ClientAckTimeout) * time.Second}
	setClientConn(hs.Reader, idleClient)
	setWriterConn(hs.Writer, idleClient)
	cltReader, cltWriter := hs.Reader, hs.Writer
	if direct && cfg.FastMode {
		if cr, ok := tgReader.(*proto.CryptoReader); ok {
			cr.Decryptor = &noopCipher{}
		}
		if cw, ok := cltWriter.(*proto.CryptoWriter); ok {
			cw.Encryptor = &noopCipher{}
		}
	}
	if !direct {
		switch {
		case bytes.Equal(hs.ProtoTag, proto.ProtoTagAbridged):
			cltReader = &proto.MtprotoCompactReader{Upstream: cltReader}
			cltWriter = &proto.MtprotoCompactWriter{Upstream: cltWriter}
		case bytes.Equal(hs.ProtoTag, proto.ProtoTagIntermediate):
			cltReader = &proto.MtprotoIntermediateReader{Upstream: cltReader}
			cltWriter = &proto.MtprotoIntermediateWriter{Upstream: cltWriter}
		case bytes.Equal(hs.ProtoTag, proto.ProtoTagSecure):
			cltReader = &proto.MtprotoSecureReader{Upstream: cltReader}
			cltWriter = &proto.MtprotoSecureWriter{Upstream: cltWriter}
		}
	}
	start := time.Now()
	done := make(chan error, 2)
	run := func(rd proto.StreamReader, wr proto.StreamWriter, up bool) {
		defer func() {
			if v := recover(); v != nil {
				Errorf("forwarding panic: %v\n%s", v, debug.Stack())
				done <- fmt.Errorf("forwarding panic: %v", v)
			}
		}()
		done <- pipeReaderToWriter(rd, wr, hs.SecretHex, 1<<17, up)
	}
	go run(tgReader, cltWriter, false)
	go run(cltReader, tgWriter, true)
	err = <-done
	// A clean half-close can still have a response in flight in the reverse
	// direction. Give it a bounded drain window; errors cancel immediately.
	if err == nil {
		select {
		case err = <-done:
		case <-time.After(time.Duration(cfg.ClientAckTimeout) * time.Second):
			conn.Close()
			tgWriter.Abort()
			<-done
		}
	} else {
		// Close is cancellation-safe even when IdleConn refreshes deadlines.
		conn.Close()
		tgWriter.Abort()
		<-done
	}
	if err != nil {
		Debugf(cfg, "forwarding stopped: %v\n", err)
	}
	stats.GlobalStats.UpdateDuration(time.Since(start).Seconds())
}

func setClientConn(rd proto.StreamReader, conn net.Conn) {
	switch r := rd.(type) {
	case *proto.TCPReader:
		r.Conn = conn
	case *proto.CryptoReader:
		setClientConn(r.Upstream, conn)
	case *proto.FakeTLSReader:
		setClientConn(r.Upstream, conn)
	}
}
func setWriterConn(wr proto.StreamWriter, conn net.Conn) {
	switch w := wr.(type) {
	case *proto.TCPWriter:
		w.Conn = conn
	case *proto.CryptoWriter:
		setWriterConn(w.Upstream, conn)
	case *proto.FakeTLSWriter:
		setWriterConn(w.Upstream, conn)
	}
}
func HandleClientWrapper(conn net.Conn, cfg *config.Config) {
	defer conn.Close()
	defer func() {
		if v := recover(); v != nil {
			Errorf("client panic from %s: %v\n%s", conn.RemoteAddr(), v, debug.Stack())
		}
	}()
	HandleClient(conn, cfg)
}
func SetKeepalive(conn net.Conn, interval int) {
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(time.Duration(interval) * time.Second)
	}
}

type noopCipher struct{}

func (*noopCipher) Encrypt(data []byte) []byte { return data }
func (*noopCipher) Decrypt(data []byte) []byte { return data }
