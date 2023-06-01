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
	SIGRTMIN_30 = syscall.Signal(0x40) // SIGRTMIN+30
)
