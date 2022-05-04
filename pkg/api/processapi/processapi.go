// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package processapi

const (
	UnresolvedMountPoints    = 0x1
	UnresolvedPathComponents = 0x2
)

const (
	// DOCKER_ID_LENGTH to match BPF side buffer size where we read the
	// cgroup of the task
	DOCKER_ID_LENGTH = 128

	MSG_SIZEOF_MAXARG = 100
	MSG_SIZEOF_EXECVE = 32
	MSG_SIZEOF_CWD    = 256
	MSG_SIZEOF_ARGS   = 1024
	MSG_SIZEOF_BUFFER = MSG_SIZEOF_ARGS +
		MSG_SIZEOF_CWD +
		MSG_SIZEOF_EXECVE + MSG_SIZEOF_EXECVE +
		MSG_SIZEOF_MAXARG

	// MsgUnixSize of msg
	MsgUnixSize uint32 = 640
)

type MsgExec struct {
	Size  uint32
	PID   uint32
	NSPID uint32
	UID   uint32
	AUID  uint32
	Flags uint32
	Ktime uint64
}

type MsgExecveKey struct {
	Pid   uint32
	Pad   uint32
	Ktime uint64
}

// API between Kernel BPF and Userspace tetragon Golang agent
type MsgCommon struct {
	Op uint8
	// Flags is used to:
	//  - distinguish between an entry and a return kprobe event
	Flags  uint8
	Pad_v2 [2]uint8
	Size   uint32
	Ktime  uint64
}

type MsgK8s struct {
	NetNS  uint32
	Cid    uint32
	Cgrpid uint64
	Docker [DOCKER_ID_LENGTH]byte
}

type MsgK8sUnix struct {
	NetNS  uint32
	Cid    uint32
	Cgrpid uint64
	Docker string
}

type MsgExecveEvent struct {
	Common       MsgCommon
	Kube         MsgK8s
	Parent       MsgExecveKey
	ParentFlags  uint64
	Capabilities MsgCapabilities
	Namespaces   MsgNamespaces
}

type MsgExecveEventUnix struct {
	Common       MsgCommon
	Kube         MsgK8sUnix
	Parent       MsgExecveKey
	ParentFlags  uint64
	Capabilities MsgCapabilities
	Namespaces   MsgNamespaces
	Process      MsgProcess
}

type MsgCloneEvent struct {
	Common MsgCommon
	Parent MsgExecveKey
	PID    uint32
	NSPID  uint32
	Flags  uint32
	Ktime  uint64
}

type MsgCloneEventUnix = MsgCloneEvent

type MsgCapabilities struct {
	Permitted   uint64
	Effective   uint64
	Inheritable uint64
}

type MsgNamespaces struct {
	UtsInum       uint32
	IpcInum       uint32
	MntInum       uint32
	PidInum       uint32
	PidChildInum  uint32
	NetInum       uint32
	TimeInum      uint32
	TimeChildInum uint32
	CgroupInum    uint32
	UserInum      uint32
}

// API between Userspace tetragon Golang agent and Unix domain socket listener
type MsgProcess struct {
	Size     uint32
	PID      uint32
	NSPID    uint32
	UID      uint32
	AUID     uint32
	Flags    uint32
	Ktime    uint64
	Filename string
	Args     string
}

type MsgExitInfo struct {
	Code uint32 `align:"code"`
	Pad1 uint32 `align:"pad"`
}

type MsgExitEvent struct {
	Common     MsgCommon    `align:"common"`
	ProcessKey MsgExecveKey `align:"current"`
	Info       MsgExitInfo  `align:"info"`
}

type MsgExitEventUnix = MsgExitEvent
