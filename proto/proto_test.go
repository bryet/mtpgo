package proto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

type memoryReader struct {
	*bytes.Reader
	maxRequest int
}

func reader(b []byte) *memoryReader { return &memoryReader{Reader: bytes.NewReader(b)} }
func (r *memoryReader) Read(n int) ([]byte, map[string]bool, error) {
	b, e := r.ReadExactly(n)
	return b, nil, e
}
func (r *memoryReader) ReadExactly(n int) ([]byte, error) {
	if n > r.maxRequest {
		r.maxRequest = n
	}
	if n < 0 || n > MaxMsgLen+16 {
		return nil, errors.New("oversized read")
	}
	b := make([]byte, n)
	_, e := io.ReadFull(r.Reader, b)
	return b, e
}

type memoryWriter struct{ bytes.Buffer }

func (w *memoryWriter) Write(b []byte, _ map[string]bool) error { _, e := w.Buffer.Write(b); return e }
func (w *memoryWriter) WriteEOF() error                         { return nil }
func (w *memoryWriter) Drain() error                            { return nil }
func (w *memoryWriter) Close()                                  {}
func (w *memoryWriter) Abort()                                  {}
func (w *memoryWriter) GetConn() net.Conn                       { return nil }

func TestProxyV1PreservesPayload(t *testing.T) {
	for _, header := range []string{"PROXY TCP4 192.0.2.1 198.51.100.1 1234 8443\r\n", "PROXY TCP6 2001:db8::1 2001:db8::2 1234 8443\r\n", "PROXY UNKNOWN\r\n"} {
		t.Run(header, func(t *testing.T) {
			r := reader(append([]byte(header), []byte("payload")...))
			peer := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9000}
			addr, err := HandleProxyProtocol(r, peer)
			if err != nil {
				t.Fatal(err)
			}
			if header != "PROXY UNKNOWN\r\n" && addr.(*net.TCPAddr).Port != 1234 {
				t.Fatal(addr)
			}
			b, _ := r.ReadExactly(7)
			if string(b) != "payload" {
				t.Fatalf("payload consumed: %q", b)
			}
		})
	}
}
func TestProxyV1RejectsInvalid(t *testing.T) {
	for _, header := range []string{"PROXY TCP4 bad 198.51.100.1 123 456\r\n", "PROXY TCP4 ::1 ::1 123 456\r\n", "PROXY TCP4 192.0.2.1 198.51.100.1 -1 456\r\n", "PROXY TCP4 192.0.2.1 198.51.100.1 123 65536\r\n", "PROXY " + string(bytes.Repeat([]byte{'x'}, 110)) + "\r\n"} {
		if _, err := HandleProxyProtocol(reader([]byte(header)), &net.TCPAddr{}); err == nil {
			t.Errorf("accepted %q", header)
		}
	}
}
func proxyV2(fam byte, body []byte) []byte {
	h := []byte{13, 10, 13, 10, 0, 13, 10, 81, 85, 73, 84, 10, 0x21, fam, 0, 0}
	binary.BigEndian.PutUint16(h[14:], uint16(len(body)))
	return append(h, body...)
}
func TestProxyV2(t *testing.T) {
	body := []byte{192, 0, 2, 1, 198, 51, 100, 1, 0x04, 0xd2, 0x20, 0xfb}
	r := reader(append(proxyV2(0x11, body), 1, 2, 3))
	a, err := HandleProxyProtocol(r, &net.TCPAddr{})
	if err != nil {
		t.Fatal(err)
	}
	if a.String() != "192.0.2.1:1234" || r.Len() != 3 {
		t.Fatal(a, r.Len())
	}
	if _, err := HandleProxyProtocol(reader(proxyV2(0x12, body)), &net.TCPAddr{}); err == nil {
		t.Fatal("accepted UDP")
	}
	if _, err := HandleProxyProtocol(reader(proxyV2(0x11, body[:5])), &net.TCPAddr{}); err == nil {
		t.Fatal("accepted truncated address")
	}
}
func TestFramesRejectUnboundedLengths(t *testing.T) {
	for _, raw := range []uint32{0, 1, 3, MaxMsgLen + 4, 0x7fffffff, 0x80000000, 0xffffffff} {
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, raw)
		for _, secure := range []bool{false, true} {
			r := reader(b)
			var fr StreamReader = &MtprotoIntermediateReader{Upstream: r}
			if secure {
				fr = &MtprotoSecureReader{Upstream: r}
			}
			if _, _, err := fr.Read(1024); err == nil {
				t.Fatalf("accepted %x", raw)
			}
			if r.maxRequest > 4 {
				t.Fatalf("allocated payload for %x", raw)
			}
		}
	}
	r := reader([]byte{0x7f, 0xff, 0xff, 0xff})
	if _, _, err := (&MtprotoCompactReader{Upstream: r}).Read(1); err == nil {
		t.Fatal("accepted compact oversized length")
	}
}
func TestFrameRoundTrips(t *testing.T) {
	payload := bytes.Repeat([]byte{1, 2, 3, 4}, 128)
	for _, kind := range []string{"compact", "intermediate", "secure", "frame"} {
		t.Run(kind, func(t *testing.T) {
			w := &memoryWriter{}
			var writer StreamWriter
			switch kind {
			case "compact":
				writer = &MtprotoCompactWriter{Upstream: w}
			case "intermediate":
				writer = &MtprotoIntermediateWriter{Upstream: w}
			case "secure":
				writer = &MtprotoSecureWriter{Upstream: w}
			case "frame":
				writer = &MtprotoFrameWriter{Upstream: w, SeqNo: -2}
			}
			if err := writer.Write(payload, nil); err != nil {
				t.Fatal(err)
			}
			r := reader(w.Bytes())
			var rd StreamReader
			switch kind {
			case "compact":
				rd = &MtprotoCompactReader{Upstream: r}
			case "intermediate":
				rd = &MtprotoIntermediateReader{Upstream: r}
			case "secure":
				rd = &MtprotoSecureReader{Upstream: r}
			case "frame":
				rd = &MtprotoFrameReader{Upstream: r, SeqNo: -2}
			}
			got, _, err := rd.Read(1)
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("roundtrip: %v", err)
			}
		})
	}
}
func TestQuickAckFlag(t *testing.T) {
	for _, secure := range []bool{false, true} {
		b := []byte{4, 0, 0, 0x80, 1, 2, 3, 4}
		var r StreamReader = &MtprotoIntermediateReader{Upstream: reader(b)}
		if secure {
			r = &MtprotoSecureReader{Upstream: reader(b)}
		}
		got, extra, err := r.Read(8)
		if err != nil || len(got) != 4 || !extra["QUICKACK_FLAG"] {
			t.Fatal(got, extra, err)
		}
	}
}
func TestFakeTLSRoundTrip(t *testing.T) {
	w := &memoryWriter{}
	payload := bytes.Repeat([]byte{1, 2}, 40000)
	if err := (&FakeTLSWriter{Upstream: w}).Write(payload, nil); err != nil {
		t.Fatal(err)
	}
	r := &FakeTLSReader{Upstream: reader(w.Bytes())}
	b, err := r.ReadExactly(len(payload))
	if err != nil || !bytes.Equal(b, payload) {
		t.Fatal(err)
	}
}
func TestIdleTimeoutAndClose(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	c := &IdleConn{Conn: a, ReadTimeout: 20 * time.Millisecond}
	defer c.Close()
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("no timeout")
	}
	c.Close()
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
}

type partialConn struct{ net.Conn }

func (partialConn) Read(p []byte) (int, error)  { copy(p, "end"); return 3, io.EOF }
func (partialConn) Write(p []byte) (int, error) { return len(p) - 1, nil }
func TestTCPPartialIO(t *testing.T) {
	data, _, err := (&TCPReader{Conn: partialConn{}}).Read(8)
	if string(data) != "end" || !errors.Is(err, io.EOF) {
		t.Fatal(data, err)
	}
	if err := (&TCPWriter{Conn: partialConn{}}).Write([]byte("data"), nil); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
}
func TestReadSizeGuards(t *testing.T) {
	for _, rd := range []StreamReader{&FakeTLSReader{Upstream: reader(nil)}, &CryptoReader{Upstream: reader(nil)}, &TCPReader{}} {
		for _, n := range []int{-1, MaxMsgLen + 17} {
			if _, err := rd.ReadExactly(n); err == nil {
				t.Fatal("invalid size accepted")
			}
		}
	}
}
func FuzzProxyProtocol(f *testing.F) {
	f.Add([]byte("PROXY UNKNOWN\r\n"))
	f.Add(proxyV2(0, nil))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = HandleProxyProtocol(reader(b), &net.TCPAddr{}) })
}
func FuzzFrameLength(f *testing.F) {
	f.Add(uint32(0))
	f.Add(uint32(0xffffffff))
	f.Fuzz(func(t *testing.T, n uint32) {
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, n)
		_, _, _ = (&MtprotoSecureReader{Upstream: reader(b)}).Read(1)
	})
}
