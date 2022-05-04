// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracingapi

import "github.com/cilium/tetragon/pkg/api/processapi"

const (
	// 5 arguments + 1 return argument
	MaxArgsSupported = 6
	ReturnArgIndex   = MaxArgsSupported - 1
)

const (
	ActionPost       = 0
	ActionFollowFd   = 1
	ActionSigKill    = 2
	ActionUnfollowFd = 3
	ActionOverride   = 4
	ActionCopyFd     = 5
)

type MsgGenericKprobe struct {
	Common       processapi.MsgCommon
	ProcessKey   processapi.MsgExecveKey
	Namespaces   processapi.MsgNamespaces
	Capabilities processapi.MsgCapabilities
	Id           uint64
	ThreadId     uint64
	ActionId     uint64
}

type MsgGenericKprobeArgPath struct {
	Index uint64
	Value string
	Flags uint32
}

func (m MsgGenericKprobeArgPath) GetIndex() uint64 {
	return m.Index
}

func (m MsgGenericKprobeArgPath) IsReturnArg() bool {
	return (m.Index == ReturnArgIndex)
}

type MsgGenericKprobeArgFile struct {
	Index uint64
	Value string
	Flags uint32
}

func (m MsgGenericKprobeArgFile) GetIndex() uint64 {
	return m.Index
}

func (m MsgGenericKprobeArgFile) IsReturnArg() bool {
	return (m.Index == ReturnArgIndex)
}

type MsgGenericKprobeArgString struct {
	Index uint64
	Value string
}

func (m MsgGenericKprobeArgString) GetIndex() uint64 {
	return m.Index
}

func (m MsgGenericKprobeArgString) IsReturnArg() bool {
	return (m.Index == ReturnArgIndex)
}

type MsgGenericKprobeArgBytes struct {
	Index    uint64
	OrigSize uint64 // if len(Value) < OrigSize, then the result was truncated
	Value    []byte
}

func (m MsgGenericKprobeArgBytes) GetIndex() uint64 {
	return m.Index
}

func (m MsgGenericKprobeArgBytes) IsReturnArg() bool {
	return m.Index == ReturnArgIndex
}

type MsgGenericKprobeArgInt struct {
	Index uint64
	Value int32
}

func (m MsgGenericKprobeArgInt) GetIndex() uint64 {
	return m.Index
}

func (m MsgGenericKprobeArgInt) IsReturnArg() bool {
	return m.Index == ReturnArgIndex
}

type MsgGenericKprobeArgSize struct {
	Index uint64
	Value uint64
}

func (m MsgGenericKprobeArgSize) GetIndex() uint64 {
	return m.Index
}

func (m MsgGenericKprobeArgSize) IsReturnArg() bool {
	return m.Index == ReturnArgIndex
}

type MsgGenericKprobeSock struct {
	Family   uint16
	Type     uint16
	Protocol uint16
	Pad      uint16
	Mark     uint32
	Priority uint32
	Saddr    uint32
	Daddr    uint32
	Sport    uint16
	Dport    uint16
}

type MsgGenericKprobeArgSock struct {
	Index    uint64
	Family   uint16
	Type     uint16
	Protocol uint16
	Mark     uint32
	Priority uint32
	Saddr    string
	Daddr    string
	Sport    uint32
	Dport    uint32
}

func (m MsgGenericKprobeArgSock) GetIndex() uint64 {
	return m.Index
}

func (m MsgGenericKprobeArgSock) IsReturnArg() bool {
	return m.Index == ReturnArgIndex
}

type MsgGenericKprobeSkb struct {
	Hash        uint32
	Len         uint32
	Priority    uint32
	Mark        uint32
	Saddr       uint32
	Daddr       uint32
	Sport       uint32
	Dport       uint32
	Proto       uint32
	SecPathLen  uint32
	SecPathOLen uint32
}

type MsgGenericKprobeArgSkb struct {
	Index       uint64
	Hash        uint32
	Len         uint32
	Priority    uint32
	Mark        uint32
	Saddr       string
	Daddr       string
	Sport       uint32
	Dport       uint32
	Proto       uint32
	SecPathLen  uint32
	SecPathOLen uint32
}

func (m MsgGenericKprobeArgSkb) GetIndex() uint64 {
	return m.Index
}

func (m MsgGenericKprobeArgSkb) IsReturnArg() bool {
	return m.Index == ReturnArgIndex
}

type MsgGenericKprobeCred struct {
	Permitted   uint64
	Effective   uint64
	Inheritable uint64
}

type MsgGenericKprobeArgCred struct {
	Index       uint64
	Permitted   uint64
	Effective   uint64
	Inheritable uint64
}

func (m MsgGenericKprobeArgCred) GetIndex() uint64 {
	return m.Index
}

func (m MsgGenericKprobeArgCred) IsReturnArg() bool {
	return m.Index == ReturnArgIndex
}

type MsgGenericKprobeArg interface {
	GetIndex() uint64
	IsReturnArg() bool
}

type MsgGenericKprobeUnix struct {
	Common       processapi.MsgCommon
	ProcessKey   processapi.MsgExecveKey
	Namespaces   processapi.MsgNamespaces
	Capabilities processapi.MsgCapabilities
	Id           uint64
	Action       uint64
	FuncName     string
	Args         []MsgGenericKprobeArg
}

type KprobeArgs struct {
	Args0 []byte
	Args1 []byte
	Args2 []byte
	Args3 []byte
	Args4 []byte
}

type EventConfig struct {
	FuncId        uint32
	Arg           [5]int32
	ArgM          [5]uint32
	ArgTpCtxOff   [5]uint32
	Sigkill       uint32
	Syscall       uint32
	ArgReturnCopy int32
}
