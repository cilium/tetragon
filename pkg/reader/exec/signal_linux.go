// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package exec

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func Signal(s uint32) string {
	if s == 0 {
		return ""
	}
	return unix.SignalName(syscall.Signal(s))
}
