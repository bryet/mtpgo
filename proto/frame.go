package proto

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"net"

	"mtproxy/crypto"
)

// ── 常量 ──────────────────────────────────────────────────────────────────────

const (
	CBCPadding = 16
	MinMsgLen  = 12
	MaxMsgLen  = 1 << 24
)

var (
	ProtoTagAbridged     = []byte{0xef, 0xef, 0xef, 0xef}
	ProtoTagIntermediate = []byte{0xee, 0xee, 0xee, 0xee}
	ProtoTagSecure       = []byte{0xdd, 0xdd, 0xdd, 0xdd}
	PaddingFiller        = []byte{0x04, 0x00, 0x00, 0x00}
)

// ── MTProto Frame 流（用于中间代理） ──────────────────────────────────────────

type MtprotoFrameReader struct {
	Upstream StreamReader
	SeqNo    int32
}

func (r *MtprotoFrameReader) ReadExactly(n int) ([]byte, error) {
	data, _, err := r.Read(n)
	return data, err
}

func (r *MtprotoFrameReader) Read(bufSize int) ([]byte, map[string]bool, error) {
	for {
		lenBytes, err := r.Upstream.ReadExactly(4)
		if err != nil {
			return nil, nil, err
		}
		msgLen := int(binary.LittleEndian.Uint32(lenBytes))
		if msgLen == 4 {
			continue // padding
		}
		if msgLen < MinMsgLen || msgLen > MaxMsgLen || msgLen%len(PaddingFiller) != 0 {
			return nil, nil, fmt.Errorf("bad msg_len: %d", msgLen)
		}
		seqBytes, err := r.Upstream.ReadExactly(4)
		if err != nil {
			return nil, nil, err
		}
		seq := int32(binary.LittleEndian.Uint32(seqBytes))
		if seq != r.SeqNo {
			return nil, nil, fmt.Errorf("unexpected seq_no: got %d want %d", seq, r.SeqNo)
		}
		r.SeqNo++
		data, err := r.Upstream.ReadExactly(msgLen - 4 - 4 - 4)
		if err != nil {
			return nil, nil, err
		}
		checksumBytes, err := r.Upstream.ReadExactly(4)
		if err != nil {
			return nil, nil, err
		}
		checksum := binary.LittleEndian.Uint32(checksumBytes)
		computed := crc32.ChecksumIEEE(append(append(lenBytes, seqBytes...), data...))
		if computed != checksum {
			return nil, nil, fmt.Errorf("crc32 mismatch")
		}
		return data, nil, nil
	}
}

type MtprotoFrameWriter struct {
	Upstream StreamWriter
	SeqNo    int32
}

func (w *MtprotoFrameWriter) Write(msg []byte, extra map[string]bool) error {
	// 预计算总长度，一次性分配，避免多次 append 拷贝
	// frame = len(4) + seq(4) + msg + crc32(4)，再对齐到 CBCPadding
	baseLen := 4 + 4 + len(msg) + 4
	padding := (CBCPadding - baseLen%CBCPadding) % CBCPadding
	full := make([]byte, 0, baseLen+padding)

	// len 字段包含整个帧（含自身），但不含 padding
	totalLen := uint32(baseLen)
	full = append(full,
		byte(totalLen), byte(totalLen>>8), byte(totalLen>>16), byte(totalLen>>24))

	seq := uint32(w.SeqNo)
	w.SeqNo++
	full = append(full,
		byte(seq), byte(seq>>8), byte(seq>>16), byte(seq>>24))

	full = append(full, msg...)

	checksum := crc32.ChecksumIEEE(full) // 对 len+seq+msg 计算 CRC32
	full = append(full,
		byte(checksum), byte(checksum>>8), byte(checksum>>16), byte(checksum>>24))

	// 补齐到 CBCPadding（16 字节）
	for i := 0; i < padding; i += len(PaddingFiller) {
		full = append(full, PaddingFiller...)
	}

	return w.Upstream.Write(full, extra)
}

func (w *MtprotoFrameWriter) WriteEOF() error   { return w.Upstream.WriteEOF() }
func (w *MtprotoFrameWriter) Drain() error      { return w.Upstream.Drain() }
func (w *MtprotoFrameWriter) Close()            { w.Upstream.Close() }
func (w *MtprotoFrameWriter) Abort()            { w.Upstream.Abort() }
func (w *MtprotoFrameWriter) GetConn() net.Conn { return w.Upstream.GetConn() }

// ── MTProto Compact (Abridged) 帧流 ──────────────────────────────────────────

type MtprotoCompactReader struct{ Upstream StreamReader }

func (r *MtprotoCompactReader) ReadExactly(n int) ([]byte, error) {
	data, _, err := r.Read(n)
	return data, err
}

func (r *MtprotoCompactReader) Read(bufSize int) ([]byte, map[string]bool, error) {
	hdr, err := r.Upstream.ReadExactly(1)
	if err != nil {
		return nil, nil, err
	}
	msgLen := int(hdr[0])
	extra := map[string]bool{}
	if msgLen >= 0x80 {
		extra["QUICKACK_FLAG"] = true
		msgLen -= 0x80
	}
	if msgLen == 0x7f {
		ext, err := r.Upstream.ReadExactly(3)
		if err != nil {
			return nil, nil, err
		}
		msgLen = int(ext[0]) | int(ext[1])<<8 | int(ext[2])<<16
	}
	msgLen *= 4
	data, err := r.Upstream.ReadExactly(msgLen)
	return data, extra, err
}

type MtprotoCompactWriter struct{ Upstream StreamWriter }

func (w *MtprotoCompactWriter) Write(data []byte, extra map[string]bool) error {
	if extra != nil && extra["SIMPLE_ACK"] {
		rev := make([]byte, len(data))
		for i, b := range data {
			rev[len(data)-1-i] = b
		}
		return w.Upstream.Write(rev, nil)
	}
	lenDiv4 := len(data) / 4
	var hdr []byte
	if lenDiv4 < 0x7f {
		hdr = []byte{byte(lenDiv4)}
	} else {
		hdr = []byte{0x7f, byte(lenDiv4), byte(lenDiv4 >> 8), byte(lenDiv4 >> 16)}
	}
	return w.Upstream.Write(append(hdr, data...), nil)
}

func (w *MtprotoCompactWriter) WriteEOF() error   { return w.Upstream.WriteEOF() }
func (w *MtprotoCompactWriter) Drain() error      { return w.Upstream.Drain() }
func (w *MtprotoCompactWriter) Close()            { w.Upstream.Close() }
func (w *MtprotoCompactWriter) Abort()            { w.Upstream.Abort() }
func (w *MtprotoCompactWriter) GetConn() net.Conn { return w.Upstream.GetConn() }

// ── MTProto Intermediate 帧流 ─────────────────────────────────────────────────

type MtprotoIntermediateReader struct{ Upstream StreamReader }

func (r *MtprotoIntermediateReader) ReadExactly(n int) ([]byte, error) {
	data, _, err := r.Read(n)
	return data, err
}

func (r *MtprotoIntermediateReader) Read(bufSize int) ([]byte, map[string]bool, error) {
	hdr, err := r.Upstream.ReadExactly(4)
	if err != nil {
		return nil, nil, err
	}
	msgLen := binary.LittleEndian.Uint32(hdr)
	extra := map[string]bool{}
	if msgLen > 0x80000000 {
		extra["QUICKACK_FLAG"] = true
		msgLen -= 0x80000000
	}
	data, err := r.Upstream.ReadExactly(int(msgLen))
	return data, extra, err
}

type MtprotoIntermediateWriter struct{ Upstream StreamWriter }

func (w *MtprotoIntermediateWriter) Write(data []byte, extra map[string]bool) error {
	if extra != nil && extra["SIMPLE_ACK"] {
		return w.Upstream.Write(data, nil)
	}
	hdr := make([]byte, 4)
	binary.LittleEndian.PutUint32(hdr, uint32(len(data)))
	return w.Upstream.Write(append(hdr, data...), nil)
}

func (w *MtprotoIntermediateWriter) WriteEOF() error   { return w.Upstream.WriteEOF() }
func (w *MtprotoIntermediateWriter) Drain() error      { return w.Upstream.Drain() }
func (w *MtprotoIntermediateWriter) Close()            { w.Upstream.Close() }
func (w *MtprotoIntermediateWriter) Abort()            { w.Upstream.Abort() }
func (w *MtprotoIntermediateWriter) GetConn() net.Conn { return w.Upstream.GetConn() }

// ── MTProto Secure Intermediate 帧流 ─────────────────────────────────────────

type MtprotoSecureReader struct{ Upstream StreamReader }

func (r *MtprotoSecureReader) ReadExactly(n int) ([]byte, error) {
	data, _, err := r.Read(n)
	return data, err
}

func (r *MtprotoSecureReader) Read(bufSize int) ([]byte, map[string]bool, error) {
	hdr, err := r.Upstream.ReadExactly(4)
	if err != nil {
		return nil, nil, err
	}
	raw := binary.LittleEndian.Uint32(hdr)
	extra := map[string]bool{}
	if raw > 0x80000000 {
		extra["QUICKACK_FLAG"] = true
		raw -= 0x80000000
	}
	msgLen := int(raw)
	data, err := r.Upstream.ReadExactly(msgLen)
	if err != nil {
		return nil, nil, err
	}
	if msgLen%4 != 0 {
		data = data[:msgLen-(msgLen%4)]
	}
	return data, extra, nil
}

type MtprotoSecureWriter struct{ Upstream StreamWriter }

func (w *MtprotoSecureWriter) Write(data []byte, extra map[string]bool) error {
	if extra != nil && extra["SIMPLE_ACK"] {
		return w.Upstream.Write(data, nil)
	}
	paddingLen := crypto.GlobalRand.Intn(4)
	padding := crypto.GlobalRand.Bytes(paddingLen)
	hdr := make([]byte, 4)
	binary.LittleEndian.PutUint32(hdr, uint32(len(data)+paddingLen))
	return w.Upstream.Write(append(append(hdr, data...), padding...), nil)
}

func (w *MtprotoSecureWriter) WriteEOF() error   { return w.Upstream.WriteEOF() }
func (w *MtprotoSecureWriter) Drain() error      { return w.Upstream.Drain() }
func (w *MtprotoSecureWriter) Close()            { w.Upstream.Close() }
func (w *MtprotoSecureWriter) Abort()            { w.Upstream.Abort() }
func (w *MtprotoSecureWriter) GetConn() net.Conn { return w.Upstream.GetConn() }
