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
	SIGRTMIN    = syscall.Signal(0x22)
	SIGRTMIN_20 = syscall.Signal(0x36) // SIGRTMIN+20
	SIGRTMIN_21 = syscall.Signal(0x37) // SIGRTMIN+21
	SIGRTMIN_22 = syscall.Signal(0x38) // SIGRTMIN+22
	SIGRTMIN_30 = syscall.Signal(0x40) // SIGRTMIN+30
)
