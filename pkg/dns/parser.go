// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// Package dns provides DNS helpers and a pure-Go reference parser that mirrors
// the on-path BPF parser at bpf/process/types/dns.h.
package dns

import "errors"

type Parsed struct {
	TxId      uint16
	Flags     uint16
	QType     uint16
	QClass    uint16
	Response  bool
	QName     string
	Truncated bool
}

var (
	ErrShort       = errors.New("dns: message shorter than header")
	ErrOpcode      = errors.New("dns: non-standard opcode")
	ErrNoQuestion  = errors.New("dns: qdcount < 1")
	ErrLabel       = errors.New("dns: invalid label length")
	ErrCompression = errors.New("dns: compression pointer in question section")
	ErrTruncated   = errors.New("dns: qname exceeded maximum length")
)

const (
	maxName     = 255
	maxLabel    = 63
	headerLen   = 12
	maxUDPBytes = 512
)

func Parse(buf []byte) (Parsed, error) {
	var p Parsed
	if len(buf) > maxUDPBytes {
		buf = buf[:maxUDPBytes]
	}
	if len(buf) < headerLen {
		return p, ErrShort
	}

	p.TxId = uint16(buf[0])<<8 | uint16(buf[1])
	p.Flags = uint16(buf[2])<<8 | uint16(buf[3])
	qdcount := uint16(buf[4])<<8 | uint16(buf[5])
	p.Response = p.Flags&0x8000 != 0
	opcode := (p.Flags >> 11) & 0xf
	if opcode != 0 {
		return p, ErrOpcode
	}
	if qdcount < 1 {
		return p, ErrNoQuestion
	}

	name := make([]byte, 0, 64)
	pos := headerLen
	for {
		if pos >= len(buf) {
			return p, ErrShort
		}
		labelLen := int(buf[pos])
		pos++
		if labelLen == 0 {
			break
		}
		// RFC 1035 §4.1.4: top two bits 11 = compression pointer.
		if labelLen&0xc0 == 0xc0 {
			return p, ErrCompression
		}
		if labelLen > maxLabel {
			return p, ErrLabel
		}
		if len(name) > 0 {
			if len(name)+1 > maxName {
				p.Truncated = true
				return p, ErrTruncated
			}
			name = append(name, '.')
		}
		if pos+labelLen > len(buf) {
			return p, ErrShort
		}
		for i := 0; i < labelLen; i++ {
			if len(name) >= maxName {
				p.Truncated = true
				return p, ErrTruncated
			}
			c := buf[pos+i]
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			name = append(name, c)
		}
		pos += labelLen
	}
	p.QName = string(name)

	if pos+4 > len(buf) {
		return p, ErrShort
	}
	p.QType = uint16(buf[pos])<<8 | uint16(buf[pos+1])
	p.QClass = uint16(buf[pos+2])<<8 | uint16(buf[pos+3])
	return p, nil
}
