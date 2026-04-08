// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

//go:generate go run github.com/cilium/tetragon/cmd/goabi-gen

package tracing

import (
	"fmt"
	"runtime"

	"github.com/cilium/tetragon/pkg/asm"
)

func archHasGoString() bool {
	return runtime.GOARCH == "amd64"
}

func errGoStringUnsupportedArch() error {
	return fmt.Errorf("go_string ABI register mapping is only supported on amd64 (GOARCH=%s)", runtime.GOARCH)
}

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

// goABISlotPtRegsOffset returns pt_regs byte offsets for the ptr/len registers of a Go string.
func goABISlotPtRegsOffset(slot int) (ptrOff, lenOff uint16, err error) {
	if !archHasGoString() {
		return 0, 0, errGoStringUnsupportedArch()
	}
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
