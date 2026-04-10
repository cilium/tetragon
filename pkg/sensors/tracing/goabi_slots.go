// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

//go:generate go run github.com/cilium/tetragon/cmd/goabi-gen

package tracing

import (
	"fmt"

	"github.com/cilium/tetragon/pkg/asm"
)

// GoABISlotForArg returns the ABI register slot for argIndex, or -1 if unknown.
func GoABISlotForArg(symbol string, argIndex int) int {
	offsets, ok := goABIKnownFuncs[symbol]
	if !ok || argIndex >= len(offsets) {
		return -1
	}
	return offsets[argIndex]
}

// https://go.googlesource.com/go/+/refs/heads/master/src/cmd/compile/abi-internal.md
var goABIIntRegs = []string{
	"rax", "rbx", "rcx", "rdi", "rsi", "r8", "r9", "r10", "r11",
}

// GoABISlotRegNames returns the ptr and len register names for a Go string at slot.
func GoABISlotRegNames(slot int) (ptrReg, lenReg string, err error) {
	if slot < 0 || slot+1 >= len(goABIIntRegs) {
		return "", "", fmt.Errorf("go ABI slot %d out of range (max %d for string)", slot, len(goABIIntRegs)-2)
	}
	return goABIIntRegs[slot], goABIIntRegs[slot+1], nil
}

// goABISlotPtRegsOffset returns pt_regs byte offsets for the ptr/len registers of a Go string.
func goABISlotPtRegsOffset(slot int) (ptrOff, lenOff uint16, err error) {
	if slot < 0 || slot+1 >= len(goABIIntRegs) {
		return 0, 0, fmt.Errorf("go ABI slot %d out of range (max %d for string)", slot, len(goABIIntRegs)-2)
	}
	ptrOff, ok := asm.RegOffset(goABIIntRegs[slot])
	if !ok {
		return 0, 0, fmt.Errorf("no pt_regs offset for register %s", goABIIntRegs[slot])
	}
	lenOff, ok = asm.RegOffset(goABIIntRegs[slot+1])
	if !ok {
		return 0, 0, fmt.Errorf("no pt_regs offset for register %s", goABIIntRegs[slot+1])
	}
	return ptrOff, lenOff, nil
}
