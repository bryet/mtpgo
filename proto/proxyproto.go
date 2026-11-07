package proto

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// HandleProxyProtocol must only be enabled on listeners reachable by trusted
// reverse proxies: the header is not authenticated. It consumes exactly one
// header, never any bytes from the subsequent MTProto/TLS handshake.
func HandleProxyProtocol(reader StreamReader, peer net.Addr) (net.Addr, error) {
	const maxLine = 108
	header, err := reader.ReadExactly(6)
	if err != nil {
		return nil, err
	}
	if bytes.Equal(header, []byte("PROXY ")) {
		for !bytes.HasSuffix(header, []byte("\r\n")) {
			if len(header) >= maxLine {
				return nil, fmt.Errorf("proxy v1 header exceeds 108 bytes")
			}
			b, err := reader.ReadExactly(1)
			if err != nil {
				return nil, err
			}
			header = append(header, b...)
		}
		parts := strings.Fields(string(header[:len(header)-2]))
		if len(parts) >= 2 && parts[1] == "UNKNOWN" {
			return peer, nil
		}
		if len(parts) != 6 || (parts[1] != "TCP4" && parts[1] != "TCP6") {
			return nil, fmt.Errorf("bad proxy v1 header")
		}
		src, dst := net.ParseIP(parts[2]), net.ParseIP(parts[3])
		if src == nil || dst == nil || (parts[1] == "TCP4") != (src.To4() != nil) || (parts[1] == "TCP4") != (dst.To4() != nil) {
			return nil, fmt.Errorf("bad proxy v1 IP family")
		}
		srcPort, err := strconv.ParseUint(parts[4], 10, 16)
		if err != nil {
			return nil, fmt.Errorf("bad proxy v1 source port: %w", err)
		}
		if _, err := strconv.ParseUint(parts[5], 10, 16); err != nil {
			return nil, fmt.Errorf("bad proxy v1 destination port: %w", err)
		}
		return &net.TCPAddr{IP: src, Port: int(srcPort)}, nil
	}
	rest, err := reader.ReadExactly(10)
	if err != nil {
		return nil, err
	}
	header = append(header, rest...)
	sig := []byte{13, 10, 13, 10, 0, 13, 10, 81, 85, 73, 84, 10}
	if !bytes.Equal(header[:12], sig) || (header[12] != 0x20 && header[12] != 0x21) {
		return nil, fmt.Errorf("bad proxy v2 signature/version/command")
	}
	length := int(binary.BigEndian.Uint16(header[14:]))
	data, err := reader.ReadExactly(length)
	if err != nil {
		return nil, err
	}
	if header[12] == 0x20 || header[13] == 0 {
		return peer, nil
	}
	switch header[13] {
	case 0x11:
		if length >= 12 {
			return &net.TCPAddr{IP: net.IP(data[:4]), Port: int(binary.BigEndian.Uint16(data[8:10]))}, nil
		}
	case 0x21:
		if length >= 36 {
			return &net.TCPAddr{IP: net.IP(data[:16]), Port: int(binary.BigEndian.Uint16(data[32:34]))}, nil
		}
	}
	return nil, fmt.Errorf("bad proxy v2 address family, transport or length")
}
