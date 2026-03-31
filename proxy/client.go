package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"mtproxy/config"
	"mtproxy/proto"
	"mtproxy/stats"
)

func pipeReaderToWriter(ctx context.Context, rd proto.StreamReader, wr proto.StreamWriter,
	secretHex string, bufSize int, isUpstream bool) {

	defer func() { recover() }()
	stat := stats.GlobalStats.GetOrCreateSecretStat(secretHex)

	for {
		data, extra, err := rd.Read(bufSize)
		if err != nil {
			return
		}
		if extra != nil && extra["SKIP_SEND"] {
			continue
		}
		if len(data) == 0 {
			wr.WriteEOF()
			return
		}
		if isUpstream {
			stat.AddOctetsFromClt(int64(len(data)))
			stat.AddMsgsFromClt(1)
		} else {
			stat.AddOctetsToClt(int64(len(data)))
			stat.AddMsgsToClt(1)
		}
		if err := wr.Write(data, extra); err != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

func HandleBadClient(conn net.Conn, handshake []byte, cfg *config.Config) {
	stats.GlobalStats.IncConnectsBad()
	if !cfg.Mask || handshake == nil {
		io.Copy(io.Discard, conn)
		return
	}
	maskConn, err := net.DialTimeout("tcp",
		fmt.Sprintf("%s:%d", cfg.MaskHost, cfg.MaskPort), 5*time.Second)
	if err != nil {
		return
	}
	defer maskConn.Close()
	if len(handshake) > 0 {
		maskConn.Write(handshake)
	}
	done := make(chan struct{}, 2)
	go func() { io.Copy(maskConn, conn); done <- struct{}{} }()
	go func() { io.Copy(conn, maskConn); done <- struct{}{} }()
	<-done
}

func HandleClient(conn net.Conn, cfg *config.Config) {
	defer conn.Close()

	SetKeepalive(conn, cfg.ClientKeepalive)
	stats.GlobalStats.IncConnectsAll()

	hsResult, handshake, err := func() (*HandshakeResult, []byte, error) {
		done := make(chan struct{})
		var res *HandshakeResult
		var hs []byte
		var hsErr error
		go func() {
			res, hs, hsErr = HandleHandshake(conn, cfg)
			close(done)
		}()
		select {
		case <-time.After(time.Duration(cfg.ClientHandshakeTimeout) * time.Second):
			stats.GlobalStats.IncHandshakeTimeouts()
			return nil, nil, fmt.Errorf("handshake timeout")
		case <-done:
			return res, hs, hsErr
		}
	}()

	if err != nil {
		Dbgf(cfg, "[DEBUG] handshake failed from %s: %v\n", conn.RemoteAddr(), err)
		if handshake != nil {
			HandleBadClient(conn, handshake, cfg)
		}
		return
	}

	Dbgf(cfg, "[DEBUG] handshake OK: proto=%x dc=%d secret=%s\n",
		hsResult.ProtoTag, hsResult.DcIdx, hsResult.SecretHex[:8])

	stat := stats.GlobalStats.GetOrCreateSecretStat(hsResult.SecretHex)
	stat.IncConnects()
	stat.AddCurrConnects(1)
	defer stat.AddCurrConnects(-1)

	var tgReader proto.StreamReader
	var tgWriter proto.StreamWriter

	clAddr := conn.RemoteAddr().(*net.TCPAddr)
	Dbgf(cfg, "[DEBUG] connecting via middleproxy dc=%d\n", hsResult.DcIdx)
	tgReader, tgWriter, err = DoMiddleproxyHandshake(hsResult.ProtoTag, hsResult.DcIdx,
		clAddr.IP.String(), clAddr.Port, cfg)

	if err != nil {
		Dbgf(cfg, "[DEBUG] TG connect failed: %v\n", err)
		return
	}
	Dbgf(cfg, "[DEBUG] TG connected OK\n")
	defer tgWriter.Abort()

	cltReader := hsResult.Reader
	cltWriter := hsResult.Writer

	if bytes.Equal(hsResult.ProtoTag, proto.ProtoTagAbridged) {
		cltReader = &proto.MtprotoCompactReader{Upstream: cltReader}
		cltWriter = &proto.MtprotoCompactWriter{Upstream: cltWriter}
	} else if bytes.Equal(hsResult.ProtoTag, proto.ProtoTagIntermediate) {
		cltReader = &proto.MtprotoIntermediateReader{Upstream: cltReader}
		cltWriter = &proto.MtprotoIntermediateWriter{Upstream: cltWriter}
	} else if bytes.Equal(hsResult.ProtoTag, proto.ProtoTagSecure) {
		cltReader = &proto.MtprotoSecureReader{Upstream: cltReader}
		cltWriter = &proto.MtprotoSecureWriter{Upstream: cltWriter}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	start := time.Now()
	done := make(chan struct{}, 2)
	go func() {
		pipeReaderToWriter(ctx, tgReader, cltWriter, hsResult.SecretHex, 1<<17, false)
		done <- struct{}{}
	}()
	go func() {
		pipeReaderToWriter(ctx, cltReader, tgWriter, hsResult.SecretHex, 1<<17, true)
		done <- struct{}{}
	}()

	<-done
	cancel()
	stats.GlobalStats.UpdateDuration(time.Since(start).Seconds())
}

func HandleClientWrapper(conn net.Conn, cfg *config.Config) {
	defer func() {
		recover()
		conn.Close()
	}()
	HandleClient(conn, cfg)
}

func SetKeepalive(conn net.Conn, interval int) {
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(time.Duration(interval) * time.Second)
	}
}
