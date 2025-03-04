// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package main

import (
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

func main() {
	var cpu, node int
	_, _, err := unix.Syscall(
		unix.SYS_GETCPU,
		uintptr(unsafe.Pointer(&cpu)),
		uintptr(unsafe.Pointer(&node)),
		0,
	)
	os.Exit(int(err))
}
