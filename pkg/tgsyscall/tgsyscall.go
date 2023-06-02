// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

/*
 * This package contains low-level operating system privimitives
 * that are missing from the the default syscall package
 */

package tgsyscall

import (
	"syscall"
)

const (
	/*
	 * The real time signals can be used for application-defined
	 * purpose.
	 *
	 * We avoid using first rt signals to easy debugging in case
	 * inspecting logs as the first rt signals are heavily used by
	 * nptl implementation to manage threads.
	 *
	 * https://man7.org/linux/man-pages/man7/signal.7.html
	 */
	SIGRTMIN    = syscall.Signal(0x22) // SIGRTMIN
	SIGRTMIN_20 = SIGRTMIN + 20        // SIGRTMIN+20 used to set log level to debug
)
