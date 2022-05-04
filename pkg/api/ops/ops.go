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

	// just for testing
	MSG_OP_TEST = 254
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
		254: "Test",
	}[op]
}
