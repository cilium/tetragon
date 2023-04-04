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
	ActionGetUrl     = 6
	ActionLookupDns  = 7
	ActionNoPost     = 8
	ActionSignal     = 9
)

const (
	BPF_OBJ_NAME_LEN = 16
	KSYM_NAME_LEN    = 128
)

type MsgLoader struct {
	Common      processapi.MsgCommon
	ProcessKey  processapi.MsgExecveKey
	Pid         uint32
	BuildIdSize uint32
	PathSize    uint32
	BuildId     [20]byte
	Path        [4096]byte
}

type MsgGenericKprobe struct {
	Common       processapi.MsgCommon
	ProcessKey   processapi.MsgExecveKey
	Namespaces   processapi.MsgNamespaces
	Capabilities processapi.MsgCapabilities
	Id           uint64
	ThreadId     uint64
	ActionId     uint64
	ActionArgId  uint32
	Pad          uint32
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

type MsgGenericKprobeArgUInt struct {
	Index uint64
	Value uint32
}

func (m MsgGenericKprobeArgUInt) GetIndex() uint64 {
	return m.Index
}

func (m MsgGenericKprobeArgUInt) IsReturnArg() bool {
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

type MsgGenericKprobeCapability struct {
	Value int32
	Pad   int32
}

type MsgGenericKprobeArgCapability struct {
	Index uint64
	Value int32
	Pad   int32
}

func (m MsgGenericKprobeArgCapability) GetIndex() uint64 {
	return m.Index
}

func (m MsgGenericKprobeArgCapability) IsReturnArg() bool {
	return m.Index == ReturnArgIndex
}

type MsgGenericKprobeUserNamespace struct {
	Level  int32
	Owner  uint32
	Group  uint32
	NsInum uint32
}

type MsgGenericKprobeArgUserNamespace struct {
	Index  uint64
	Level  int32
	Owner  uint32
	Group  uint32
	NsInum uint32
}

func (m MsgGenericKprobeArgUserNamespace) GetIndex() uint64 {
	return m.Index
}

func (m MsgGenericKprobeArgUserNamespace) IsReturnArg() bool {
	return m.Index == ReturnArgIndex
}

type MsgGenericKprobeBpfAttr struct {
	ProgType uint32
	InsnCnt  uint32
	ProgName [BPF_OBJ_NAME_LEN]byte
}

type MsgGenericKprobeArgBpfAttr struct {
	Index    uint64
	ProgType uint32
	InsnCnt  uint32
	ProgName string
}

func (m MsgGenericKprobeArgBpfAttr) GetIndex() uint64 {
	return m.Index
}

func (m MsgGenericKprobeArgBpfAttr) IsReturnArg() bool {
	return m.Index == ReturnArgIndex
}

type MsgGenericKprobePerfEvent struct {
	KprobeFunc  [KSYM_NAME_LEN]byte
	Type        uint32
	Config      uint64
	ProbeOffset uint64
}

type MsgGenericKprobeArgPerfEvent struct {
	Index       uint64
	KprobeFunc  string
	Type        uint32
	Config      uint64
	ProbeOffset uint64
}

func (m MsgGenericKprobeArgPerfEvent) GetIndex() uint64 {
	return m.Index
}

func (m MsgGenericKprobeArgPerfEvent) IsReturnArg() bool {
	return m.Index == ReturnArgIndex
}

type MsgGenericKprobeBpfMap struct {
	MapType    uint32
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	MapName    [BPF_OBJ_NAME_LEN]byte
}

type MsgGenericKprobeArgBpfMap struct {
	MapType    uint32
	Index      uint64
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	MapName    string
}

func (m MsgGenericKprobeArgBpfMap) GetIndex() uint64 {
	return m.Index
}

func (m MsgGenericKprobeArgBpfMap) IsReturnArg() bool {
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

const EventConfigMaxArgs = 5

type EventConfig struct {
	FuncId        uint32                     `align:"func_id"`
	Arg           [EventConfigMaxArgs]int32  `align:"arg0"`
	ArgM          [EventConfigMaxArgs]uint32 `align:"arg0m"`
	ArgTpCtxOff   [EventConfigMaxArgs]uint32 `align:"t_arg0_ctx_off"`
	Syscall       uint32                     `align:"syscall"`
	ArgReturnCopy int32                      `align:"argreturncopy"`
	ArgReturn     int32                      `align:"argreturn"`
	PolicyID      uint32                     `align:"policy_id"`
	Flags         uint32                     `align:"flags"`
}
