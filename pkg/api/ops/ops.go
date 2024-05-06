// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package ops

import (
	"fmt"

	"github.com/cilium/tetragon/pkg/logger"
)

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
	MSG_OP_GENERIC_UPROBE     = 15

	// MSG_OP_CLONE notifies user-space that a clone() event has occurred.
	MSG_OP_CLONE = 23

	MSG_OP_DATA = 24

	MSG_OP_CGROUP = 25

	MSG_OP_LOADER = 26

	MSG_OP_THROTTLE = 27

	// just for testing
	MSG_OP_TEST = 254
)

type CgroupOpCode int

// Cgroup Operations that are sent from BPF side. Right now
// they are used only for logging and debugging, except for
// CGROUP_ATTACH_TASK which will be used to detect cgroup
// configuration.
const (
	MSG_OP_CGROUP_UNDEF       CgroupOpCode = iota
	MSG_OP_CGROUP_MKDIR       CgroupOpCode = 1
	MSG_OP_CGROUP_RMDIR       CgroupOpCode = 2
	MSG_OP_CGROUP_RELEASE     CgroupOpCode = 3
	MSG_OP_CGROUP_ATTACH_TASK CgroupOpCode = 10
)

type CgroupState int

// Different cgroup states.
const (
	CGROUP_UNTRACKED    CgroupState = iota // Cgroup was created but we did not track it
	CGROUP_NEW          CgroupState = 1    // Cgroup was just created
	CGROUP_RUNNING      CgroupState = 2    // Cgroup from new => running (fork,exec task inside)
	CGROUP_RUNNING_PROC CgroupState = 3    // Cgroups that were generated from pids of procfs
	_CGROUP_STATE_MAX   CgroupState = 4
)

type OpCode int

const (
	MsgOpUndef              = iota
	MsgOpExecve             = 5
	MsgOpExit               = 7
	MsgOpKfreeSkb           = 11
	MsgOpGenericKprobe      = 13
	MsgOpGeneric_Tracepoint = 14
	MsgOpGenericUprobe      = 15
	MsgOpClone              = 23
	MsgOpData               = 24
	MsgOpCgroup             = 25
	MsgOpLoader             = 26
	MsgOpTest               = 254
)

var OpCodeStrings = map[OpCode]string{
	MsgOpUndef:              "Undef",
	MsgOpExecve:             "Execve",
	MsgOpExit:               "Exit",
	MsgOpKfreeSkb:           "KfreeSkb",
	MsgOpGenericKprobe:      "GenericKprobe",
	MsgOpGeneric_Tracepoint: "GenericTracepoint",
	MsgOpGenericUprobe:      "GenericUprobe",
	MsgOpClone:              "Clone",
	MsgOpData:               "Data",
	MsgOpCgroup:             "Cgroup",
	MsgOpLoader:             "Loader",
	MsgOpTest:               "Test",
}

func (op OpCode) String() string {
	s, ok := OpCodeStrings[op]
	if !ok {
		logger.GetLogger().WithField("opcode", op).Info("Unknown OpCode. This is a bug, please report it to Tetragon developers.")
		return fmt.Sprintf("Unknown(%d)", op)
	}
	return s
}

func (op CgroupOpCode) String() string {
	return [...]string{
		MSG_OP_CGROUP_UNDEF:       "Undef",
		MSG_OP_CGROUP_MKDIR:       "CgroupMkdir",
		MSG_OP_CGROUP_RMDIR:       "CgroupRmdir",
		MSG_OP_CGROUP_RELEASE:     "CgroupRelease",
		MSG_OP_CGROUP_ATTACH_TASK: "CgroupAttachTask",
	}[op]
}

func (st CgroupState) String() string {
	return [...]string{
		CGROUP_UNTRACKED:    "Untracked",
		CGROUP_NEW:          "New",
		CGROUP_RUNNING:      "Running",
		CGROUP_RUNNING_PROC: "RunningProc",
	}[st]
}
