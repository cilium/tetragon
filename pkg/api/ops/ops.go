// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package ops

const (
	MSG_OP_UNDEF = 0
	// MSG_OP_EXECVE event indicates a process was created. The 'PID'
	// and 'Common' fields will be populated. This event is positioned
	// after exec() calls have been validated so failed syscalls will
	// not be reported. To generate events provide the '-e' option to
	// tetragon, without the option the hook only populates the data
	// store for later use by above events.
	MSG_OP_EXECVE = 5
	MSG_OP_EXIT   = 7

	MSG_OP_GENERIC_KPROBE     = 13
	MSG_OP_GENERIC_TRACEPOINT = 14

	// MSG_OP_CLONE notifies user-space that a clone() event has occurred.
	MSG_OP_CLONE = 23

	MSG_OP_DATA = 24

	MSG_OP_CGROUP = 25

	// just for testing
	MSG_OP_TEST = 254
)

const (
	MSG_OP_CGROUP_UNDEF       = iota
	MSG_OP_CGROUP_MKDIR       = 1
	MSG_OP_CGROUP_RMDIR       = 2
	MSG_OP_CGROUP_RELEASE     = 3
	MSG_OP_CGROUP_ATTACH_TASK = 10
)

const (
	CGROUP_UNTRACKED    = iota // Cgroup was created but we did not track it
	CGROUP_NEW          = 1    // Cgroup was just created
	CGROUP_RUNNING      = 2    // Cgroup from new => running (fork,exec task inside)
	CGROUP_RUNNING_PROC = 3    // Cgroups that were generated from pids of procfs
)

type OpCode int

const (
	MsgOpUndef              = iota
	MsgOpExecve             = 5
	MsgOpExit               = 7
	MsgOpKfreeSkb           = 11
	MsgOpGenericKprobe      = 13
	MsgOpGeneric_Tracepoint = 14
	MsgOpTest               = 254
)

func (op OpCode) String() string {
	return [...]string{
		0:   "Undef",
		5:   "Execve",
		7:   "Exit",
		13:  "GenericKprobe",
		14:  "GenericTracepoint",
		23:  "Clone",
		24:  "Data",
		25:  "Cgroup",
		254: "Test",
	}[op]
}

type CgroupOpCode int

func (op CgroupOpCode) String() string {
	return [...]string{
		0:  "Undef",
		1:  "CgroupMkdir",
		2:  "CgroupRmdir",
		3:  "CgroupRelease",
		10: "CgroupAttachTask",
	}[op]
}

type CgroupState int

func (st CgroupState) String() string {
	return [...]string{
		0: "Untracked",
		1: "New",
		2: "Running",
		3: "RunningProc",
	}[st]
}
