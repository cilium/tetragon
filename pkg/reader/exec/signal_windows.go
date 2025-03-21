// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package exec

import (
	"sort"
	"syscall"
)

// Signal table
var signalList = [...]struct {
	num  syscall.Signal
	name string
	desc string
}{
	{1, "SIGHUP", "hangup"},
	{2, "SIGINT", "interrupt"},
	{3, "SIGQUIT", "quit"},
	{4, "SIGILL", "illegal instruction"},
	{5, "SIGTRAP", "trace/breakpoint trap"},
	{6, "SIGABRT", "aborted"},
	{7, "SIGBUS", "bus error"},
	{8, "SIGFPE", "floating point exception"},
	{9, "SIGKILL", "killed"},
	{10, "SIGUSR1", "user defined signal 1"},
	{11, "SIGSEGV", "segmentation fault"},
	{12, "SIGUSR2", "user defined signal 2"},
	{13, "SIGPIPE", "broken pipe"},
	{14, "SIGALRM", "alarm clock"},
	{15, "SIGTERM", "terminated"},
	{16, "SIGSTKFLT", "stack fault"},
	{17, "SIGCHLD", "child exited"},
	{18, "SIGCONT", "continued"},
	{19, "SIGSTOP", "stopped (signal)"},
	{20, "SIGTSTP", "stopped"},
	{21, "SIGTTIN", "stopped (tty input)"},
	{22, "SIGTTOU", "stopped (tty output)"},
	{23, "SIGURG", "urgent I/O condition"},
	{24, "SIGXCPU", "CPU time limit exceeded"},
	{25, "SIGXFSZ", "file size limit exceeded"},
	{26, "SIGVTALRM", "virtual timer expired"},
	{27, "SIGPROF", "profiling timer expired"},
	{28, "SIGWINCH", "window changed"},
	{29, "SIGIO", "I/O possible"},
	{30, "SIGPWR", "power failure"},
	{31, "SIGSYS", "bad system call"},
}

// SignalName returns the signal name for signal number s.
func SignalName(s syscall.Signal) string {
	i := sort.Search(len(signalList), func(i int) bool {
		return signalList[i].num >= s
	})
	if i < len(signalList) && signalList[i].num == s {
		return signalList[i].name
	}
	return ""
}

func Signal(s uint32) string {
	if s == 0 {
		return ""
	}
	return SignalName(syscall.Signal(s))
}
