// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build arm64 && linux

package asm

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

var ptregs unix.PtraceRegs

func RegOffset(name string) (uint16, bool) {
	if name == "sp" {
		return uint16(unsafe.Offsetof(ptregs.Sp)), true
	}
	var idx int
	_, err := fmt.Sscanf(name, "x%d", &idx)
	if err == nil && idx >= 0 && idx <= 31 {
		if idx == 31 {
			return RegOffset("sp")
		}
		baseOff := unsafe.Offsetof(ptregs.Regs)
		shift := unsafe.Sizeof(ptregs.Regs[0]) * uintptr(idx)
		return uint16(baseOff + shift), true
	}
	return 0, false
}
