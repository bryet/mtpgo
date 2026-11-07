package proxy

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"mtproxy/config"
	"mtproxy/crypto"
	"mtproxy/proto"
	"mtproxy/stats"
)

func testConfig() *config.Config {
	c := config.DefaultConfig()
	c.Secrets = [][]byte{bytes.Repeat([]byte{0x35}, 16)}
	c.Mask = false
	return c
}

type testReader struct{ *bytes.Reader }

func readMemory(b []byte) *testReader { return &testReader{bytes.NewReader(b)} }
func (r *testReader) Read(n int) ([]byte, map[string]bool, error) {
	b := make([]byte, n)
	got, err := r.Reader.Read(b)
	return b[:got], nil, err
}
func (r *testReader) ReadExactly(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := io.ReadFull(r.Reader, b)
	return b, err
}

type testWriter struct{ bytes.Buffer }

func (w *testWriter) Write(b []byte, _ map[string]bool) error {
	_, err := w.Buffer.Write(b)
	return err
}
func (w *testWriter) WriteEOF() error   { return nil }
func (w *testWriter) Drain() error      { return nil }
func (w *testWriter) Close()            {}
func (w *testWriter) Abort()            {}
func (w *testWriter) GetConn() net.Conn { return nil }

func TestReplayConcurrentAndResize(t *testing.T) {
	r := NewReplayCache(10)
	var successes atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r.CheckAndAdd([]byte("same")) {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("accepted %d duplicates", successes.Load())
	}
	for _, key := range []string{"b", "c", "d", "e", "f", "g", "h", "i", "j", "k"} {
		r.CheckAndAdd([]byte(key))
	}
	r.Resize(2)
	if r.CheckAndAdd([]byte("k")) {
		t.Fatal("resize lost newest")
	}
	if !r.CheckAndAdd([]byte("old")) {
		t.Fatal("old key retained")
	}
	r.Resize(0)
	if !r.CheckAndAdd([]byte("old")) || len(r.cache) != 0 {
		t.Fatal("disabled cache stores entries")
	}
	r.Resize(8)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				r.Resize(4 + j%4)
				r.CheckAndAdd([]byte{byte(j)})
			}
		}()
	}
	wg.Wait()
}

func clientHandshake(secret, tag []byte, dc int) []byte {
	h := crypto.GlobalRand.Bytes(64)
	h[0] = 0x42
	copy(h[56:], tag)
	binary.LittleEndian.PutUint16(h[60:], uint16(int16(dc)))
	key := sha256.Sum256(append(append([]byte(nil), h[8:40]...), secret...))
	encrypted := crypto.NewAESCTR(key[:], crypto.Uint128FromBytes(h[40:56])).Encrypt(h)
	copy(h[56:], encrypted[56:])
	return h
}
func runHandshake(t *testing.T, data []byte, c *config.Config) (*HandshakeResult, error) {
	t.Helper()
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	server.SetDeadline(time.Now().Add(time.Second))
	done := make(chan error, 1)
	go func() { _, err := client.Write(data); done <- err }()
	result, _, err := HandleHandshake(server, c)
	client.Close()
	<-done
	return result, err
}
func TestHandshakeProxyAddressAndReplay(t *testing.T) {
	c := testConfig()
	c.ProxyProtocol = true
	h := clientHandshake(c.Secrets[0], proto.ProtoTagSecure, 2)
	data := append([]byte("PROXY TCP4 192.0.2.8 198.51.100.9 2345 8443\r\n"), h...)
	result, err := runHandshake(t, data, c)
	if err != nil {
		t.Fatal(err)
	}
	if result.Peer.String() != "192.0.2.8:2345" || result.DcIdx != 2 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if _, err := runHandshake(t, data, c); err == nil {
		t.Fatal("replay accepted")
	}
}
func TestHandshakeModesAndDC(t *testing.T) {
	for _, tc := range []struct {
		tag             []byte
		dc              int
		classic, secure bool
		want            bool
	}{{proto.ProtoTagAbridged, 1, true, false, true}, {proto.ProtoTagIntermediate, -2, true, false, true}, {proto.ProtoTagSecure, 1, false, true, true}, {proto.ProtoTagSecure, 1, true, false, false}, {proto.ProtoTagAbridged, 1, false, true, false}, {proto.ProtoTagSecure, 0, false, true, false}, {proto.ProtoTagSecure, 6, false, true, false}} {
		c := testConfig()
		c.Modes = config.Modes{Classic: tc.classic, Secure: tc.secure}
		result, err := runHandshake(t, clientHandshake(c.Secrets[0], tc.tag, tc.dc), c)
		if (err == nil) != tc.want {
			t.Fatalf("case %+v result=%+v err=%v", tc, result, err)
		}
	}
}

func helloBytes() []byte {
	body := append([]byte{3, 3}, bytes.Repeat([]byte{0}, 32)...)
	body = append(body, 0, 0, 4, 0x13, 1, 0x13, 2, 1, 0)
	// supported_versions TLS 1.3; signature algorithms; ALPN h2
	exts := []byte{0, 43, 0, 3, 2, 3, 4, 0, 13, 0, 6, 0, 4, 4, 3, 8, 4, 0, 16, 0, 5, 0, 3, 2, 'h', '2'}
	body = append(body, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)
	n := len(body)
	return append([]byte{1, byte(n >> 16), byte(n >> 8), byte(n)}, body...)
}
func TestFingerprints(t *testing.T) {
	h, err := parseClientHello(helloBytes())
	if err != nil {
		t.Fatal(err)
	}
	if h.alpn != "h2" || h.maxTLSVer != 0x0304 || len(h.signatures) != 2 {
		t.Fatalf("%+v", h)
	}
	if !validTLSClientHello(helloBytes(), testConfig()) {
		t.Fatal("valid hello rejected")
	}
	sum := sha256.Sum256([]byte("1301,1302"))
	want := hex.EncodeToString(sum[:6])
	if hashList16([]uint16{0x1301, 0x1302}) != want {
		t.Fatal("nonstandard cipher hash")
	}
	sum = sha256.Sum256([]byte("000d,002b_0403,0804"))
	ext := hex.EncodeToString(sum[:6])
	want = "t13i0203h2_" + want + "_" + ext
	if got := buildJA4(h); got != want {
		t.Fatalf("JA4=%s want=%s", got, want)
	}
	if hashList16(nil) != "000000000000" {
		t.Fatal("incorrect empty hash")
	}
	if isGREASE(0x1a2a) || !isGREASE(0x1a1a) {
		t.Fatal("GREASE detection")
	}
	h.alpn = "a "
	if got := buildJA4(h); !bytes.Contains([]byte(got), []byte("60_")) {
		t.Fatal(got)
	}
	if len(buildJA3(h)) != 32 {
		t.Fatal("nonstandard JA3 digest length")
	}
}
func TestLegacyBlacklistStillEnforced(t *testing.T) {
	hello := helloBytes()
	h, err := parseLegacyClientHello(hello)
	if err != nil {
		t.Fatal(err)
	}
	key := buildLegacyJA3(h)
	previous, present := blockedJA3[key]
	blockedJA3[key] = true
	defer func() {
		if present {
			blockedJA3[key] = previous
		} else {
			delete(blockedJA3, key)
		}
	}()
	if verifyTLSFingerprint(hello, testConfig()) {
		t.Fatal("legacy blacklist bypassed")
	}
}
func TestClientHelloMalformed(t *testing.T) {
	hello := helloBytes()
	for i := 0; i < len(hello); i++ {
		if _, err := parseClientHello(hello[:i]); err == nil {
			t.Fatalf("accepted truncation %d", i)
		}
	}
	odd := append([]byte(nil), hello...)
	odd[40] = 3
	if _, err := parseClientHello(odd); err == nil {
		t.Fatal("accepted odd cipher vector")
	}
	if _, _, err := handleFakeTLSHandshake([]byte{1}, readMemory(nil), &testWriter{}, &net.TCPAddr{}, testConfig()); err == nil {
		t.Fatal("short handshake accepted")
	}
}
func TestFakeTLSHMACAndReplay(t *testing.T) {
	c := testConfig()
	c.Modes = config.Modes{TLS: true}
	hello := helloBytes()
	record := append([]byte{0x16, 3, 1, byte(len(hello) >> 8), byte(len(hello))}, hello...)
	mac := hmac.New(sha256.New, c.Secrets[0])
	mac.Write(record)
	digest := mac.Sum(nil)
	ts := make([]byte, 4)
	binary.LittleEndian.PutUint32(ts, uint32(time.Now().Unix()))
	for i := 0; i < 4; i++ {
		digest[28+i] ^= ts[i]
	}
	copy(record[11:43], digest)
	w := &testWriter{}
	if _, _, err := handleFakeTLSHandshake(record, readMemory(nil), w, &net.TCPAddr{}, c); err != nil {
		t.Fatal(err)
	}
	if w.Len() == 0 {
		t.Fatal("no server hello")
	}
	if _, _, err := handleFakeTLSHandshake(record, readMemory(nil), &testWriter{}, &net.TCPAddr{}, c); err == nil {
		t.Fatal("TLS replay accepted")
	}
	c.Modes.TLS = false
	if _, _, err := handleFakeTLSHandshake(record, readMemory(nil), &testWriter{}, &net.TCPAddr{}, c); err == nil {
		t.Fatal("disabled TLS accepted")
	}
}
func TestHandshakeTimeoutClassification(t *testing.T) {
	c := testConfig()
	c.ClientHandshakeTimeout = 1
	before := atomic.LoadInt64(&stats.GlobalStats.HandshakeTimeouts)
	server, client := net.Pipe()
	client.Close()
	HandleClient(server, c)
	if atomic.LoadInt64(&stats.GlobalStats.HandshakeTimeouts) != before {
		t.Fatal("EOF classified as timeout")
	}
	server, client = net.Pipe()
	defer client.Close()
	HandleClient(server, c)
	if atomic.LoadInt64(&stats.GlobalStats.HandshakeTimeouts) != before+1 {
		t.Fatal("real timeout not counted")
	}
}
func TestBadClientBounded(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() { conn, _ := ln.Accept(); accepted <- conn }()
	c := testConfig()
	c.Mask = true
	c.MaskHost = "127.0.0.1"
	c.MaskPort = ln.Addr().(*net.TCPAddr).Port
	c.ClientHandshakeTimeout = 1
	server, client := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan struct{})
	go func() { HandleBadClient(server, []byte("bad"), c); close(done) }()
	mask := <-accepted
	defer mask.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("bad client hangs")
	}
}
func TestBadClientHalfClosePreservesReply(t *testing.T) {
	maskListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer maskListener.Close()
	clientListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientListener.Close()
	client, err := net.Dial("tcp4", clientListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	server, err := clientListener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	c := testConfig()
	c.Mask = true
	c.MaskHost = "127.0.0.1"
	c.MaskPort = maskListener.Addr().(*net.TCPAddr).Port
	c.ClientHandshakeTimeout = 2
	done := make(chan struct{})
	go func() { HandleBadClient(server, []byte("prefix"), c); close(done) }()
	upstream, err := maskListener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	upstream.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := client.Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	client.(*net.TCPConn).CloseWrite()
	got, err := io.ReadAll(upstream)
	if err != nil || string(got) != "prefixpayload" {
		t.Fatalf("forwarded=%q err=%v", got, err)
	}
	upstream.Write([]byte("reply"))
	upstream.(*net.TCPConn).CloseWrite()
	reply, err := io.ReadAll(client)
	if err != nil || string(reply) != "reply" {
		t.Fatalf("reply=%q err=%v", reply, err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("forwarder did not exit")
	}
}
func TestMiddleHandshakeDeadline(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	start := time.Now()
	_, _, _, _, err := middleproxyHandshake(a, 20*time.Millisecond)
	var nerr net.Error
	if !errors.As(err, &nerr) || !nerr.Timeout() || time.Since(start) > time.Second {
		t.Fatalf("timeout missing: %v", err)
	}
}
func TestProxyResponsesRejectTruncation(t *testing.T) {
	for _, magic := range [][4]byte{rpcProxyAns, rpcSimpleAck} {
		for n := 4; n < 16; n++ {
			b := make([]byte, n)
			copy(b, magic[:])
			if _, _, err := (&proxyReqReader{upstream: readMemory(b)}).Read(64); err == nil {
				t.Fatal("accepted truncated response")
			}
		}
	}
}
func TestProxyListValidation(t *testing.T) {
	p, err := parseProxyList([]byte("proxy_for 1 192.0.2.1:8888;\nproxy_for -2 [2001:db8::1]:80;"))
	if err != nil || len(p) != 2 {
		t.Fatal(p, err)
	}
	for _, s := range []string{
		"", "proxy_for 0 192.0.2.1:80;", "proxy_for 1 bad:80;", "proxy_for 1 192.0.2.1:65536;",
		"proxy_for 999999999999999999999999 192.0.2.1:80;",
		"proxy_for 203 192.0.2.203:8888;\nproxy_for 1 bad:80;",
		"proxy_for -203 [2001:db8::203]:80;\nproxy_for 1 192.0.2.1:65536;",
	} {
		if _, err := parseProxyList([]byte(s)); err == nil {
			t.Fatal(s)
		}
	}
}
func TestProxyListSkipsUnsupportedDCs(t *testing.T) {
	body := []byte("proxy_for 203 192.0.2.203:8888;\n" +
		"proxy_for 1 192.0.2.1:8888;\n" +
		"proxy_for -203 [2001:db8::203]:80;\n" +
		"proxy_for -2 [2001:db8::2]:80;\n" +
		"proxy_for 1 192.0.2.11:8888;\n" +
		"proxy_for 6 192.0.2.6:8888;")
	proxies, err := parseProxyList(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(proxies) != 2 || len(proxies[1]) != 2 || len(proxies[-2]) != 1 {
		t.Fatalf("supported proxies were lost: %v", proxies)
	}
	if proxies[1][0] != [2]interface{}{"192.0.2.1", 8888} || proxies[-2][0] != [2]interface{}{"2001:db8::2", 80} {
		t.Fatalf("unexpected proxy addresses: %v", proxies)
	}
	for _, dc := range []int{203, -203, 6} {
		if _, ok := proxies[dc]; ok {
			t.Fatalf("unsupported DC %d retained", dc)
		}
	}
}

func TestProxyListRequiresSupportedDC(t *testing.T) {
	_, err := parseProxyList([]byte("proxy_for 203 192.0.2.203:8888;\nproxy_for -203 [2001:db8::203]:80;"))
	if err == nil || err.Error() != "no supported DCs in proxy list" {
		t.Fatalf("expected no-supported-DC error, got %v", err)
	}
}

func TestFetchBodyRejectsStatusAndSize(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
	}{{500, "bad"}, {200, "oversized"}} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.status); io.WriteString(w, tc.body) }))
		_, err := fetchBody(t.Context(), srv.Client(), srv.URL, 3)
		srv.Close()
		if err == nil {
			t.Fatal("response accepted")
		}
	}
}
func TestLogReloadConcurrent(t *testing.T) {
	var b bytes.Buffer
	SetLogger(&b)
	defer SetLogger(io.Discard)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				SetLogLevel("debug")
				Debugf(testConfig(), "test\n")
				SetLogLevel("warn")
				Infof("test\n")
			}
		}()
	}
	wg.Wait()
	SetLogLevel("info")
}
func FuzzClientHello(f *testing.F) {
	f.Add(helloBytes())
	f.Add([]byte{1, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		if h, err := parseClientHello(b); err == nil {
			_ = buildJA3(h)
			_ = buildJA4(h)
		}
		_ = verifyTLSFingerprint(b, testConfig())
	})
}
