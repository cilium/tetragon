// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package asm

import (
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

var ptregs unix.PtraceRegs

func parseArmRegisterIndex(name, prefix string, max int) (int, bool) {
	idxStr, ok := strings.CutPrefix(name, prefix)
	if !ok || idxStr == "" {
		return 0, false
	}

	for _, ch := range idxStr {
		if ch < '0' || ch > '9' {
			return 0, false
		}
	}

	idx, err := strconv.Atoi(idxStr)
	if err != nil || idx > max {
		return 0, false
	}

	return idx, true
}

func RegOffset(name string) (uint16, bool) {
	switch name {
	case "sp":
		return uint16(unsafe.Offsetof(ptregs.Sp)), true
	case "pc":
		return uint16(unsafe.Offsetof(ptregs.Pc)), true
	}
	idx, ok := parseArmRegisterIndex(name, "x", 31)
	if ok {
		if idx == 31 {
			return RegOffset("sp")
		}
		baseOff := unsafe.Offsetof(ptregs.Regs)
		shift := unsafe.Sizeof(ptregs.Regs[0]) * uintptr(idx)
		return uint16(baseOff + shift), true
	}

	idx, ok = parseArmRegisterIndex(name, "w", 30)
	if ok {
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

	_, isWReg := parseArmRegisterIndex(name, "w", 30)
	if isWReg {
		return off, 4, true
	}

	return off, 8, true
}
