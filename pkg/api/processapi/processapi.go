// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package processapi

const (
	// UnresolvedMountPoints    = 0x1 // (deprecated)
	UnresolvedPathComponents = 0x2
)

const (
	// DOCKER_ID_LENGTH to match BPF side buffer size where we read the
	// cgroup of the task
	DOCKER_ID_LENGTH = 128

	// Length of the cgroup name as it is returned from BPF side
	CGROUP_NAME_LENGTH = 128

	// Length of the cgroup path as it is returned from BPF side
	CGROUP_PATH_LENGTH = 4096

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
	Pid   uint32 `align:"pid"`
	Pad   uint32 `align:"pad"`
	Ktime uint64 `align:"ktime"`
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

// MsgCgroupData is complementary cgroup data that is collected from
// BPF side on various cgroup events.
type MsgCgroupData struct {
	State     uint32 // State of cgroup
	Hierarchy uint32 // Unique id for the hierarchy
	Level     uint32 // The depth this cgroup is at
	Pad       uint32
	Name      [CGROUP_NAME_LENGTH]byte // Cgroup kernfs_node name
}

// MsgCgroupEvent is the data that is sent from BPF side on cgroup events
// into ring buffer.
type MsgCgroupEvent struct {
	Common        MsgCommon
	Parent        MsgExecveKey
	CgrpOp        uint32 // Current cgroup operation
	PID           uint32
	NSPID         uint32
	Flags         uint32
	Ktime         uint64
	CgrpidTracker uint64                   // The tracking cgroup ID
	Cgrpid        uint64                   // Current cgroup ID
	CgrpData      MsgCgroupData            // Complementary cgroup data
	Path          [CGROUP_PATH_LENGTH]byte // Full path of the cgroup on fs
}
