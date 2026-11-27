// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// Package javaagent implements the tetragon side of the jvmti agent
// protocol: the control channel and the data ring buffer.
package javaagent

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Wire formats shared with the jvmti agent, mirrors jvmti/proto.h (keep
// in sync). All integers are little-endian, strings are encoded as u16
// length followed by the bytes.

const ProtoVersion = 1

// Control channel messages. The agent opens the session with MsgHello and
// gets MsgAck back, then it serves commands. MsgRing is one of them, the
// data ring is set up only for a session that needs it.
const (
	MsgMaxSize = 64 * 1024

	MsgHello        = 1
	MsgRing         = 2
	MsgHookAdd      = 3
	MsgPolicyCommit = 4
	MsgPolicyRemove = 5
	MsgAck          = 6

	MsgHdrSize = 8 // u16 type, u16 flags, u32 seq
)

// Header is the fixed header on every control message.
type Header struct {
	Type  uint16
	Flags uint16
	Seq   uint32
}

// Message encodes a control message, rejecting payloads larger than the
// protocol's maximum packet size.
func (h Header) Message(payload []byte) ([]byte, error) {
	if len(payload)+MsgHdrSize > MsgMaxSize {
		return nil, fmt.Errorf("java agent message too large: %d", len(payload)+MsgHdrSize)
	}
	out := make([]byte, MsgHdrSize+len(payload))
	binary.LittleEndian.PutUint16(out[0:2], h.Type)
	binary.LittleEndian.PutUint16(out[2:4], h.Flags)
	binary.LittleEndian.PutUint32(out[4:8], h.Seq)
	copy(out[MsgHdrSize:], payload)
	return out, nil
}

// ParseMessage decodes one complete SOCK_SEQPACKET control message.
func ParseMessage(data []byte) (Header, []byte, error) {
	if len(data) < MsgHdrSize || len(data) > MsgMaxSize {
		return Header{}, nil, fmt.Errorf("invalid Java agent message size %d", len(data))
	}
	h := Header{
		Type:  binary.LittleEndian.Uint16(data[0:2]),
		Flags: binary.LittleEndian.Uint16(data[2:4]),
		Seq:   binary.LittleEndian.Uint32(data[4:8]),
	}
	return h, data[MsgHdrSize:], nil
}

func appendString(dst []byte, value string) ([]byte, error) {
	if len(value) > 0xffff {
		return nil, fmt.Errorf("java agent string too long: %d", len(value))
	}
	var size [2]byte
	binary.LittleEndian.PutUint16(size[:], uint16(len(value)))
	dst = append(dst, size[:]...)
	return append(dst, value...), nil
}

func readString(data []byte, off *int) (string, error) {
	if *off+2 > len(data) {
		return "", errors.New("truncated Java agent string length")
	}
	n := int(binary.LittleEndian.Uint16(data[*off : *off+2]))
	*off += 2
	if n > len(data)-*off {
		return "", fmt.Errorf("truncated Java agent string: need %d bytes", n)
	}
	s := string(data[*off : *off+n])
	*off += n
	return s, nil
}

type HookMethod struct {
	Name       string
	Descriptor string
}

type Hook struct {
	PolicyID uint32
	HookID   uint32
	Kind     uint8
	Class    string
	Methods  []HookMethod
}

// EncodeHook matches TG_MSG_HOOK_ADD in jvmti/proto.h.
func EncodeHook(h Hook) ([]byte, error) {
	if h.Kind != HookClass && h.Kind != HookPrefix {
		return nil, fmt.Errorf("invalid Java hook kind %d", h.Kind)
	}
	if len(h.Methods) > 0xffff {
		return nil, fmt.Errorf("too many Java hook methods: %d", len(h.Methods))
	}
	out := make([]byte, 12)
	binary.LittleEndian.PutUint32(out[0:4], h.PolicyID)
	binary.LittleEndian.PutUint32(out[4:8], h.HookID)
	out[8] = h.Kind
	binary.LittleEndian.PutUint16(out[10:12], uint16(len(h.Methods)))
	var err error
	out, err = appendString(out, h.Class)
	if err != nil {
		return nil, err
	}
	for _, method := range h.Methods {
		out, err = appendString(out, method.Name)
		if err != nil {
			return nil, err
		}
		out, err = appendString(out, method.Descriptor)
		if err != nil {
			return nil, err
		}
	}
	if len(out)+MsgHdrSize > MsgMaxSize {
		return nil, errors.New("encoded Java hook exceeds message limit")
	}
	return out, nil
}

func DecodeHook(data []byte) (Hook, error) {
	if len(data) < 14 {
		return Hook{}, errors.New("truncated Java hook")
	}
	h := Hook{
		PolicyID: binary.LittleEndian.Uint32(data[0:4]),
		HookID:   binary.LittleEndian.Uint32(data[4:8]),
		Kind:     data[8],
	}
	if h.Kind != HookClass && h.Kind != HookPrefix {
		return Hook{}, fmt.Errorf("invalid Java hook kind %d", h.Kind)
	}
	n := int(binary.LittleEndian.Uint16(data[10:12]))
	off := 12
	var err error
	h.Class, err = readString(data, &off)
	if err != nil {
		return Hook{}, err
	}
	h.Methods = make([]HookMethod, 0, n)
	for range n {
		var method HookMethod
		method.Name, err = readString(data, &off)
		if err != nil {
			return Hook{}, err
		}
		method.Descriptor, err = readString(data, &off)
		if err != nil {
			return Hook{}, err
		}
		h.Methods = append(h.Methods, method)
	}
	if off != len(data) {
		return Hook{}, fmt.Errorf("trailing bytes in Java hook: %d", len(data)-off)
	}
	return h, nil
}

// Hook kinds.
const (
	HookClass  = 1
	HookPrefix = 2
)

// Data ring layout.
const (
	RingMagic   = 0x4a56544d
	RingVersion = 1
	RingHdrSize = 4096
)

// Ring records.
const (
	RecAlign   = 8
	RecHdrSize = 8 // u32 len, u32 type

	RecPad         = 1
	RecMethodDef   = 2
	RecMethodEntry = 3
)
