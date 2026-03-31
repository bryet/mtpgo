package proto

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"mtproxy/crypto"
)

// ── 基础接口 ──────────────────────────────────────────────────────────────────

type StreamReader interface {
	Read(n int) ([]byte, map[string]bool, error)
	ReadExactly(n int) ([]byte, error)
}

type StreamWriter interface {
	Write(data []byte, extra map[string]bool) error
	WriteEOF() error
	Drain() error
	Close()
	Abort()
	GetConn() net.Conn
}

// ── 基础 TCP 流 ───────────────────────────────────────────────────────────────

type TCPReader struct {
	Conn net.Conn
}

func (r *TCPReader) Read(n int) ([]byte, map[string]bool, error) {
	buf := make([]byte, n)
	got, err := r.Conn.Read(buf)
	if err != nil {
		return nil, nil, err
	}
	return buf[:got], nil, nil
}

func (r *TCPReader) ReadExactly(n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(r.Conn, buf)
	return buf, err
}

type TCPWriter struct {
	Conn net.Conn
}

func (w *TCPWriter) Write(data []byte, extra map[string]bool) error {
	_, err := w.Conn.Write(data)
	return err
}

func (w *TCPWriter) WriteEOF() error {
	if tc, ok := w.Conn.(*net.TCPConn); ok {
		return tc.CloseWrite()
	}
	return nil
}

func (w *TCPWriter) Drain() error      { return nil }
func (w *TCPWriter) Close()            { w.Conn.Close() }
func (w *TCPWriter) Abort()            { w.Conn.Close() }
func (w *TCPWriter) GetConn() net.Conn { return w.Conn }

// ── FakeTLS 流 ────────────────────────────────────────────────────────────────

type FakeTLSReader struct {
	Upstream StreamReader
	Buf      []byte
}

func (r *FakeTLSReader) ReadExactly(n int) ([]byte, error) {
	for len(r.Buf) < n {
		data, _, err := r.readRecord()
		if err != nil {
			return nil, err
		}
		r.Buf = append(r.Buf, data...)
	}
	out := make([]byte, n)
	copy(out, r.Buf[:n])
	r.Buf = r.Buf[n:]
	return out, nil
}

func (r *FakeTLSReader) Read(n int) ([]byte, map[string]bool, error) {
	if len(r.Buf) > 0 {
		out := r.Buf
		r.Buf = nil
		return out, nil, nil
	}
	data, _, err := r.readRecord()
	return data, nil, err
}

func (r *FakeTLSReader) readRecord() ([]byte, byte, error) {
	for {
		recType, err := r.Upstream.ReadExactly(1)
		if err != nil {
			return nil, 0, err
		}
		version, err := r.Upstream.ReadExactly(2)
		if err != nil {
			return nil, 0, err
		}
		if version[0] != 0x03 {
			return nil, 0, fmt.Errorf("unknown TLS version: %x", version)
		}
		lenBytes, err := r.Upstream.ReadExactly(2)
		if err != nil {
			return nil, 0, err
		}
		dataLen := int(binary.BigEndian.Uint16(lenBytes))
		data, err := r.Upstream.ReadExactly(dataLen)
		if err != nil {
			return nil, 0, err
		}
		if recType[0] == 0x14 { // change cipher spec, skip
			continue
		}
		return data, recType[0], nil
	}
}

type FakeTLSWriter struct {
	Upstream StreamWriter
}

func (w *FakeTLSWriter) Write(data []byte, extra map[string]bool) error {
	const maxChunk = 16384 + 24
	for start := 0; start < len(data); start += maxChunk {
		end := start + maxChunk
		if end > len(data) {
			end = len(data)
		}
		chunk := data[start:end]
		hdr := []byte{0x17, 0x03, 0x03, byte(len(chunk) >> 8), byte(len(chunk))}
		if err := w.Upstream.Write(hdr, nil); err != nil {
			return err
		}
		if err := w.Upstream.Write(chunk, nil); err != nil {
			return err
		}
	}
	return nil
}

func (w *FakeTLSWriter) WriteEOF() error   { return w.Upstream.WriteEOF() }
func (w *FakeTLSWriter) Drain() error      { return w.Upstream.Drain() }
func (w *FakeTLSWriter) Close()            { w.Upstream.Close() }
func (w *FakeTLSWriter) Abort()            { w.Upstream.Abort() }
func (w *FakeTLSWriter) GetConn() net.Conn { return w.Upstream.GetConn() }

// ── Crypto 流 ─────────────────────────────────────────────────────────────────

type CryptoReader struct {
	Upstream  StreamReader
	Decryptor crypto.Cipher
	BlockSize int
	Buf       []byte
}

func (r *CryptoReader) ReadExactly(n int) ([]byte, error) {
	for len(r.Buf) < n {
		toRead := n - len(r.Buf)
		aligned := toRead
		if r.BlockSize > 1 {
			rem := toRead % r.BlockSize
			if rem != 0 {
				aligned += r.BlockSize - rem
			}
		}
		raw, err := r.Upstream.ReadExactly(aligned)
		if err != nil {
			return nil, err
		}
		r.Buf = append(r.Buf, r.Decryptor.Decrypt(raw)...)
	}
	out := make([]byte, n)
	copy(out, r.Buf[:n])
	r.Buf = r.Buf[n:]
	return out, nil
}

func (r *CryptoReader) Read(n int) ([]byte, map[string]bool, error) {
	if len(r.Buf) > 0 {
		out := r.Buf
		r.Buf = nil
		return out, nil, nil
	}
	raw, extra, err := r.Upstream.Read(n)
	if err != nil || len(raw) == 0 {
		return raw, extra, err
	}
	return r.Decryptor.Decrypt(raw), extra, nil
}

type CryptoWriter struct {
	Upstream  StreamWriter
	Encryptor crypto.Cipher
	BlockSize int
}

func (w *CryptoWriter) Write(data []byte, extra map[string]bool) error {
	if w.BlockSize > 1 && len(data)%w.BlockSize != 0 {
		return fmt.Errorf("data len %d not aligned to block size %d", len(data), w.BlockSize)
	}
	return w.Upstream.Write(w.Encryptor.Encrypt(data), extra)
}

func (w *CryptoWriter) WriteEOF() error   { return w.Upstream.WriteEOF() }
func (w *CryptoWriter) Drain() error      { return w.Upstream.Drain() }
func (w *CryptoWriter) Close()            { w.Upstream.Close() }
func (w *CryptoWriter) Abort()            { w.Upstream.Abort() }
func (w *CryptoWriter) GetConn() net.Conn { return w.Upstream.GetConn() }
