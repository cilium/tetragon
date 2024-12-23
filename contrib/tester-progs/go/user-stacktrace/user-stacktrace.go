// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package main

import (
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

//nolint:all
func main() {
	// This test has endless loop for stable stack trace collection.
	// It must be terminated from tests.
	var cpu, node int
	_, _, err := unix.Syscall(
		unix.SYS_GETCPU,
		uintptr(unsafe.Pointer(&cpu)),
		uintptr(unsafe.Pointer(&node)),
		0,
	)
	if err != 0 {
		os.Exit(int(err))
	}
	for {
		time.Sleep(time.Minute)
	}
}
