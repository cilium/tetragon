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
	MSG_SIZEOF_EXECVE = 56
	MSG_SIZEOF_CWD    = 256
	MSG_SIZEOF_ARGS   = 1024
	MSG_SIZEOF_BUFFER = MSG_SIZEOF_ARGS +
		MSG_SIZEOF_CWD +
		MSG_SIZEOF_EXECVE + MSG_SIZEOF_EXECVE +
		MSG_SIZEOF_MAXARG

	// MsgUnixSize of msg
	MsgUnixSize uint32 = 640

	/* Execve extra flags */
	ExecveSetuid = 0x01
	ExecveSetgid = 0x02
	/* Execve flags received from BPF */
	ExecveFileCaps   = 0x04 // This binary execution gained new capabilities through file capabilities execution
	ExecveSetuidRoot = 0x08 // This binary execution gained new capabilities through setuid root execution
	ExecveSetgidRoot = 0x10 // This binary execution gained new capabilities through setgid root execution

	// flags of MsgCommon
	MSG_COMMON_FLAG_RETURN            = 0x1
	MSG_COMMON_FLAG_KERNEL_STACKTRACE = 0x2
	MSG_COMMON_FLAG_USER_STACKTRACE   = 0x4
	MSG_COMMON_FLAG_IMA_HASH          = 0x8
	MSG_COMMON_FLAG_PROCESS_NOT_FOUND = 0x16

	BINARY_PATH_MAX_LEN = 256
	MAX_ARG_LENGTH      = 256

	STRING_POSTFIX_MAX_LENGTH = 128
)

const (
	SentFailedUnknown = iota
	SentFailedEnoent
	SentFailedE2big
	SentFailedEbusy
	SentFailedEinval
	SentFailedEnospc
	SentFailedMax
)

type MsgExec struct {
	Size       uint32
	PID        uint32
	TID        uint32
	NSPID      uint32
	SecureExec uint32
	UID        uint32
	AUID       uint32
	Flags      uint32
	Nlink      uint32
	Pad        uint32
	Ino        uint64
	Ktime      uint64
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
	//  - indicate if a stack trace id was passed in the event
	Flags  uint8
	Pad_v2 [2]uint8
	Size   uint32
	Ktime  uint64
}

type MsgK8s struct {
	Cgrpid        uint64
	CgrpTrackerID uint64
	Docker        [DOCKER_ID_LENGTH]byte
}

type MsgK8sUnix struct {
	Docker        string
	Cgrpid        uint64
	CgrpTrackerID uint64
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
	Cap        MsgCapabilities
	UserNs     MsgUserNamespace
}

type MsgExecveEvent struct {
	Common         MsgCommon
	Kube           MsgK8s
	Parent         MsgExecveKey
	ParentFlags    uint64
	Creds          MsgGenericCred
	Namespaces     MsgNamespaces
	CleanupProcess MsgExecveKey
}

type MsgExecveEventUnix struct {
	Msg     *MsgExecveEvent
	Kube    MsgK8sUnix
	Process MsgProcess
}

type MsgCloneEvent struct {
	Common MsgCommon
	Parent MsgExecveKey
	PID    uint32
	TID    uint32
	NSPID  uint32
	Flags  uint32
	Ktime  uint64
}

type MsgCapabilities struct {
	Permitted   uint64
	Effective   uint64
	Inheritable uint64
}

type Binary struct {
	PathLength int32
	Reversed   uint32
	Path       [BINARY_PATH_MAX_LEN]byte
	End        [STRING_POSTFIX_MAX_LENGTH]byte
	End_r      [STRING_POSTFIX_MAX_LENGTH]byte
	Args       [MAX_ARG_LENGTH]byte
	MBSet      uint64
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

type MsgUserNamespace struct {
	Level  int32
	Uid    uint32
	Gid    uint32
	NsInum uint32
}

type MsgUserRecord struct {
	Name string
}

// API between Userspace tetragon Golang agent and Unix domain socket listener
type MsgProcess struct {
	Size       uint32
	PID        uint32
	TID        uint32
	NSPID      uint32
	SecureExec uint32
	UID        uint32
	AUID       uint32
	Flags      uint32
	Nlink      uint32
	Ino        uint64
	Ktime      uint64
	Filename   string
	Args       string
	User       MsgUserRecord
}

type MsgExitInfo struct {
	Code uint32 `align:"code"`
	Tid  uint32 `align:"tid"`
}

type MsgExitEvent struct {
	Common     MsgCommon    `align:"common"`
	ProcessKey MsgExecveKey `align:"current"`
	Info       MsgExitInfo  `align:"info"`
}

// MsgCgroupData is complementary cgroup data that is collected from
// BPF side on various cgroup events.
type MsgCgroupData struct {
	State       int32                    `align:"state"`        // State of cgroup
	HierarchyId uint32                   `align:"hierarchy_id"` // Unique id for the hierarchy
	Level       uint32                   `align:"level"`        // The depth this cgroup is at
	Pad         uint32                   `align:"pad"`
	Name        [CGROUP_NAME_LENGTH]byte `align:"name"` // Cgroup kernfs_node name
}

// MsgCgroupEvent is the data that is sent from BPF side on cgroup events
// into ring buffer.
type MsgCgroupEvent struct {
	Common        MsgCommon                `align:"common"`
	Parent        MsgExecveKey             `align:"parent"`
	CgrpOp        uint32                   `align:"cgrp_op"` // Current cgroup operation
	PID           uint32                   `align:"pid"`
	NSPID         uint32                   `align:"nspid"`
	Flags         uint32                   `align:"flags"`
	Ktime         uint64                   `align:"ktime"`
	CgrpidTracker uint64                   `align:"cgrpid_tracker"` // The tracking cgroup ID
	Cgrpid        uint64                   `align:"cgrpid"`         // Current cgroup ID
	CgrpData      MsgCgroupData            `align:"cgrp_data"`      // Complementary cgroup data
	Path          [CGROUP_PATH_LENGTH]byte `align:"path"`           // Full path of the cgroup on fs
}

type MsgThrottleEvent struct {
	Common MsgCommon
	Kube   MsgK8s
}

type KernelStats struct {
	SentFailed [256][SentFailedMax]uint64 `align:"sent_failed"`
}

type CgroupRateKey struct {
	Id uint64
}

type CgroupRateValue struct {
	Curr      uint64
	Prev      uint64
	Time      uint64
	Rate      uint64
	Throttled uint64
}

type CgroupRateOptions struct {
	Events   uint64
	Interval uint64
}
