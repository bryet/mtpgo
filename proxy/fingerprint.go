package proxy

import (
	"crypto/md5" // JA3 specifies MD5; this is a diagnostic identifier, not authentication.
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"mtproxy/config"
)

type tlsHello struct {
	legacyVer, maxTLSVer                  uint16
	ciphers, extTypes, curves, signatures []uint16
	pointFmts                             []byte
	sniPresent                            bool
	alpn                                  string
	cipherCount, extCount                 int
}

func isGREASE(v uint16) bool { return v&0x0f0f == 0x0a0a && byte(v>>8) == byte(v) }

// Parse a complete ClientHello, rejecting truncated vectors instead of silently
// clamping their lengths. Record reassembly is handled by the handshake layer.
func parseClientHello(hello []byte) (*tlsHello, error) {
	if len(hello) < 42 || hello[0] != 1 || int(hello[1])<<16|int(hello[2])<<8|int(hello[3]) != len(hello)-4 {
		return nil, fmt.Errorf("invalid ClientHello length/type")
	}
	h := &tlsHello{legacyVer: binary.BigEndian.Uint16(hello[4:6])}
	pos := 38
	vec8 := func() ([]byte, error) {
		if pos >= len(hello) {
			return nil, fmt.Errorf("truncated vector")
		}
		n := int(hello[pos])
		pos++
		if n > len(hello)-pos {
			return nil, fmt.Errorf("truncated vector")
		}
		v := hello[pos : pos+n]
		pos += n
		return v, nil
	}
	vec16 := func() ([]byte, error) {
		if pos+2 > len(hello) {
			return nil, fmt.Errorf("truncated vector")
		}
		n := int(binary.BigEndian.Uint16(hello[pos:]))
		pos += 2
		if n > len(hello)-pos {
			return nil, fmt.Errorf("truncated vector")
		}
		v := hello[pos : pos+n]
		pos += n
		return v, nil
	}
	sid, err := vec8()
	if err != nil || len(sid) > 32 {
		return nil, fmt.Errorf("invalid session ID")
	}
	cs, err := vec16()
	if err != nil || len(cs) == 0 || len(cs)%2 != 0 {
		return nil, fmt.Errorf("invalid cipher suites")
	}
	for i := 0; i < len(cs); i += 2 {
		v := binary.BigEndian.Uint16(cs[i:])
		if !isGREASE(v) {
			h.ciphers = append(h.ciphers, v)
		}
	}
	compression, err := vec8()
	if err != nil || len(compression) == 0 {
		return nil, fmt.Errorf("invalid compression vector")
	}
	h.cipherCount = len(h.ciphers)
	if pos == len(hello) {
		return h, nil
	}
	exts, err := vec16()
	if err != nil || pos != len(hello) {
		return nil, fmt.Errorf("invalid extensions length")
	}
	seen := make(map[uint16]bool)
	for len(exts) > 0 {
		if len(exts) < 4 {
			return nil, fmt.Errorf("truncated extension")
		}
		typ, n := binary.BigEndian.Uint16(exts), int(binary.BigEndian.Uint16(exts[2:]))
		exts = exts[4:]
		if n > len(exts) {
			return nil, fmt.Errorf("truncated extension data")
		}
		d := exts[:n]
		exts = exts[n:]
		if isGREASE(typ) {
			continue
		}
		if seen[typ] {
			return nil, fmt.Errorf("duplicate extension")
		}
		seen[typ] = true
		h.extTypes = append(h.extTypes, typ)
		switch typ {
		case 0:
			if len(d) < 2 || int(binary.BigEndian.Uint16(d)) != len(d)-2 {
				return nil, fmt.Errorf("invalid SNI list")
			}
			for names := d[2:]; len(names) > 0; {
				if len(names) < 3 {
					return nil, fmt.Errorf("invalid SNI name")
				}
				t, n := names[0], int(binary.BigEndian.Uint16(names[1:]))
				names = names[3:]
				if n == 0 || n > len(names) {
					return nil, fmt.Errorf("invalid SNI name length")
				}
				if t == 0 {
					h.sniPresent = true
				}
				names = names[n:]
			}
		case 10, 13:
			if len(d) < 2 || int(binary.BigEndian.Uint16(d)) != len(d)-2 || (len(d)-2)%2 != 0 {
				return nil, fmt.Errorf("invalid uint16 vector")
			}
			for i := 2; i < len(d); i += 2 {
				v := binary.BigEndian.Uint16(d[i:])
				if !isGREASE(v) {
					if typ == 10 {
						h.curves = append(h.curves, v)
					} else {
						h.signatures = append(h.signatures, v)
					}
				}
			}
		case 11:
			if len(d) < 1 || int(d[0]) != len(d)-1 {
				return nil, fmt.Errorf("invalid point formats")
			}
			h.pointFmts = append(h.pointFmts, d[1:]...)
		case 16:
			if len(d) < 2 || int(binary.BigEndian.Uint16(d)) != len(d)-2 {
				return nil, fmt.Errorf("invalid ALPN list")
			}
			first := true
			for protocols := d[2:]; len(protocols) > 0; {
				n := int(protocols[0])
				protocols = protocols[1:]
				if n == 0 || n > len(protocols) {
					return nil, fmt.Errorf("invalid ALPN value")
				}
				if first {
					h.alpn = string(protocols[:n])
					first = false
				}
				protocols = protocols[n:]
			}
		case 43:
			if len(d) < 1 || int(d[0]) != len(d)-1 || (len(d)-1)%2 != 0 {
				return nil, fmt.Errorf("invalid supported versions")
			}
			for i := 1; i < len(d); i += 2 {
				v := binary.BigEndian.Uint16(d[i:])
				if !isGREASE(v) && v > h.maxTLSVer {
					h.maxTLSVer = v
				}
			}
		}
	}
	h.extCount = len(h.extTypes)
	return h, nil
}

func buildJA3(h *tlsHello) string {
	join := func(v []uint16) string {
		s := make([]string, len(v))
		for i, n := range v {
			s[i] = fmt.Sprint(n)
		}
		return strings.Join(s, "-")
	}
	points := make([]uint16, len(h.pointFmts))
	for i, n := range h.pointFmts {
		points[i] = uint16(n)
	}
	raw := fmt.Sprintf("%d,%s,%s,%s,%s", h.legacyVer, join(h.ciphers), join(h.extTypes), join(h.curves), join(points))
	sum := md5.Sum([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func hexList(vals []uint16) string {
	s := make([]string, len(vals))
	for i, v := range vals {
		s[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(s, ",")
}
func hashText(s string) string { sum := sha256.Sum256([]byte(s)); return hex.EncodeToString(sum[:6]) }
func hashList16(vals []uint16) string {
	if len(vals) == 0 {
		return "000000000000"
	}
	return hashText(hexList(vals))
}
func sorted16(vals []uint16) []uint16 {
	v := append([]uint16(nil), vals...)
	sort.Slice(v, func(i, j int) bool { return v[i] < v[j] })
	return v
}

func buildJA4(h *tlsHello) string {
	v := h.maxTLSVer
	if v == 0 {
		v = h.legacyVer
	}
	versions := map[uint16]string{0x0301: "10", 0x0302: "11", 0x0303: "12", 0x0304: "13"}
	ver := versions[v]
	if ver == "" {
		ver = "00"
	}
	sni := "i"
	if h.sniPresent {
		sni = "d"
	}
	alpn := "00"
	if h.alpn != "" {
		ascii := func(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' }
		p := h.alpn
		if !ascii(p[0]) || !ascii(p[len(p)-1]) {
			p = hex.EncodeToString([]byte(p))
		}
		alpn = string([]byte{p[0], p[len(p)-1]})
	}
	var exts []uint16
	for _, e := range h.extTypes {
		if e != 0 && e != 16 {
			exts = append(exts, e)
		}
	}
	extHash := "000000000000"
	if len(exts) > 0 {
		raw := hexList(sorted16(exts))
		if len(h.signatures) > 0 {
			raw += "_" + hexList(h.signatures)
		}
		extHash = hashText(raw)
	}
	return fmt.Sprintf("t%s%s%02d%02d%s_%s_%s", ver, sni, min(h.cipherCount, 99), min(h.extCount, 99), alpn, hashList16(sorted16(h.ciphers)), extHash)
}

// Standard fingerprints supplement the existing legacy blacklist; secret-based
// HMAC authentication remains mandatory. Legacy hashes are not interchangeable
// with the standard diagnostic identifiers.
func validTLSClientHello(hello []byte, cfg *config.Config) bool {
	h, err := parseClientHello(hello)
	if err != nil {
		Debugf(cfg, "ClientHello parse error: %v\n", err)
		return false
	}
	v := h.maxTLSVer
	if v == 0 {
		v = h.legacyVer
	}
	if v != 0x0303 && v != 0x0304 || h.cipherCount == 0 {
		return false
	}
	Debugf(cfg, "JA3=%s JA4=%s\n", buildJA3(h), buildJA4(h))
	return true
}
