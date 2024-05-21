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
	ActionPost         = 0
	ActionFollowFd     = 1
	ActionSigKill      = 2
	ActionUnfollowFd   = 3
	ActionOverride     = 4
	ActionCopyFd       = 5
	ActionGetUrl       = 6
	ActionLookupDns    = 7
	ActionNoPost       = 8
	ActionSignal       = 9
	ActionTrackSock    = 10
	ActionUntrackSock  = 11
	ActionNotifyKiller = 12
)

const (
	BPF_OBJ_NAME_LEN = 16
	KSYM_NAME_LEN    = 128
	MODULE_NAME_LEN  = 64
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
	FuncId       uint64
	RetProbeId   uint64
	ActionId     uint64
	ActionArgId  uint32
	Tid          uint32 // The recorded TID that triggered the event
	StackID      int64
}

type MsgGenericKprobeArgPath struct {
	Index uint64
	Value string
	Flags uint32
	Label string
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
	Label string
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
	Label string
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
	Label    string
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
	Label string
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
	Label string
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
	Label string
}

func (m MsgGenericKprobeArgSize) GetIndex() uint64 {
	return m.Index
}

func (m MsgGenericKprobeArgSize) IsReturnArg() bool {
	return m.Index == ReturnArgIndex
}

type MsgGenericKprobeTuple struct {
	Saddr    [2]uint64
	Daddr    [2]uint64
	Sport    uint16
	Dport    uint16
	Protocol uint16
	Family   uint16
}

type MsgGenericKprobeSock struct {
	Tuple    MsgGenericKprobeTuple
	Sockaddr uint64
	Mark     uint32
	Priority uint32
	Type     uint16
	State    uint8
	Pad      [5]uint8
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
	Sockaddr uint64
	Label    string
	State    uint8
}

func (m MsgGenericKprobeArgSock) GetIndex() uint64 {
	return m.Index
}

func (m MsgGenericKprobeArgSock) IsReturnArg() bool {
	return m.Index == ReturnArgIndex
}

type MsgGenericKprobeSkb struct {
	Tuple       MsgGenericKprobeTuple
	Hash        uint32
	Len         uint32
	Priority    uint32
	Mark        uint32
	SecPathLen  uint32
	SecPathOLen uint32
}

type MsgGenericKprobeArgSkb struct {
	Index       uint64
	Family      uint16
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
	Label       string
}

func (m MsgGenericKprobeArgSkb) GetIndex() uint64 {
	return m.Index
}

func (m MsgGenericKprobeArgSkb) IsReturnArg() bool {
	return m.Index == ReturnArgIndex
}

type MsgGenericCred struct {
	Uid        uint32
	Gid        uint32
	Suid       uint32
	Sgid       uint32
	Euid       uint32
	Egid       uint32
	FSuid      uint32
	FSgid      uint32
	SecureBits uint32
	Pad        uint32
	Cap        processapi.MsgCapabilities
	UserNs     processapi.MsgUserNamespace
}

type MsgGenericKprobeArgCred struct {
	Index      uint64
	Uid        uint32
	Gid        uint32
	Suid       uint32
	Sgid       uint32
	Euid       uint32
	Egid       uint32
	FSuid      uint32
	FSgid      uint32
	SecureBits uint32
	Pad        uint32
	Cap        processapi.MsgCapabilities
	UserNs     processapi.MsgUserNamespace
	Label      string
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
	Label string
}

func (m MsgGenericKprobeArgCapability) GetIndex() uint64 {
	return m.Index
}

func (m MsgGenericKprobeArgCapability) IsReturnArg() bool {
	return m.Index == ReturnArgIndex
}

type MsgGenericKernelCapType struct {
	Caps uint64
}

type MsgGenericKprobeArgKernelCapType struct {
	Index uint64
	Caps  uint64
	Label string
}

func (m MsgGenericKprobeArgKernelCapType) GetIndex() uint64 {
	return m.Index
}

func (m MsgGenericKprobeArgKernelCapType) IsReturnArg() bool {
	return m.Index == ReturnArgIndex
}

type MsgGenericCapInheritable struct {
	Caps uint64
}

type MsgGenericKprobeArgCapInheritable struct {
	Index uint64
	Caps  uint64
	Label string
}

func (m MsgGenericKprobeArgCapInheritable) GetIndex() uint64 {
	return m.Index
}

func (m MsgGenericKprobeArgCapInheritable) IsReturnArg() bool {
	return m.Index == ReturnArgIndex
}

type MsgGenericCapPermitted struct {
	Caps uint64
}

type MsgGenericKprobeArgCapPermitted struct {
	Index uint64
	Caps  uint64
	Label string
}

func (m MsgGenericKprobeArgCapPermitted) GetIndex() uint64 {
	return m.Index
}

func (m MsgGenericKprobeArgCapPermitted) IsReturnArg() bool {
	return m.Index == ReturnArgIndex
}

type MsgGenericCapEffective struct {
	Caps uint64
}

type MsgGenericKprobeArgCapEffective struct {
	Index uint64
	Caps  uint64
	Label string
}

func (m MsgGenericKprobeArgCapEffective) GetIndex() uint64 {
	return m.Index
}

func (m MsgGenericKprobeArgCapEffective) IsReturnArg() bool {
	return m.Index == ReturnArgIndex
}

type MsgGenericUserNamespace struct {
	Level  int32
	Uid    uint32
	Gid    uint32
	NsInum uint32
}

type MsgGenericKprobeArgUserNamespace struct {
	Index  uint64
	Level  int32
	Uid    uint32
	Gid    uint32
	NsInum uint32
	Label  string
}

func (m MsgGenericKprobeArgUserNamespace) GetIndex() uint64 {
	return m.Index
}

func (m MsgGenericKprobeArgUserNamespace) IsReturnArg() bool {
	return m.Index == ReturnArgIndex
}

type MsgGenericLoadModule struct {
	SigOk  uint32
	Pad    uint32
	Taints uint64
	Name   [MODULE_NAME_LEN]byte
}

type MsgGenericKprobeArgLoadModule struct {
	Index  uint64
	SigOk  uint32
	Taints uint64
	Name   string
	Label  string
}

func (m MsgGenericKprobeArgLoadModule) GetIndex() uint64 {
	return m.Index
}

func (m MsgGenericKprobeArgLoadModule) IsReturnArg() bool {
	return m.Index == ReturnArgIndex
}

type MsgGenericKprobeArgKernelModule struct {
	Index  uint64
	Name   string
	Taints uint64
	Label  string
}

func (m MsgGenericKprobeArgKernelModule) GetIndex() uint64 {
	return m.Index
}

func (m MsgGenericKprobeArgKernelModule) IsReturnArg() bool {
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
	Label    string
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
	Label       string
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
	Label      string
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
	FuncId          uint32                     `align:"func_id"`
	Arg             [EventConfigMaxArgs]int32  `align:"arg0"`
	ArgM            [EventConfigMaxArgs]uint32 `align:"arg0m"`
	ArgTpCtxOff     [EventConfigMaxArgs]uint32 `align:"t_arg0_ctx_off"`
	Syscall         uint32                     `align:"syscall"`
	ArgReturnCopy   int32                      `align:"argreturncopy"`
	ArgReturn       int32                      `align:"argreturn"`
	ArgReturnAction int32                      `align:"argreturnaction"`
	PolicyID        uint32                     `align:"policy_id"`
	Flags           uint32                     `align:"flags"`
}
