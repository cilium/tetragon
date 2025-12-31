// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package asm

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

var ptregs unix.PtraceRegs

func RegOffset(name string) (uint16, bool) {
	switch name {
	case "sp":
		return uint16(unsafe.Offsetof(ptregs.Sp)), true
	case "pc":
		return uint16(unsafe.Offsetof(ptregs.Pc)), true
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

	_, err = fmt.Sscanf(name, "w%d", &idx)
	if err == nil && idx >= 0 && idx <= 30 {
		baseOff := unsafe.Offsetof(ptregs.Regs)
		shift := unsafe.Sizeof(ptregs.Regs[0]) * uintptr(idx)
		return uint16(baseOff + shift), true
	}

	return 0, false
}

func RegOffsetSize(name string) (uint16, uint8, bool) {
	off, ok := RegOffset(name)
	if !ok {
		return 0, 0, false
	}

	var idx int
	_, err := fmt.Sscanf(name, "w%d", &idx)
	if err == nil {
		return off, 4, true
	}

	return off, 8, true
}
