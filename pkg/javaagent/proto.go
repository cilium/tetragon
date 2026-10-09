// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// Package javaagent implements the tetragon side of the jvmti agent
// protocol: the control channel and the data ring buffer.
package javaagent

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
