// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

//go:generate go run github.com/cilium/tetragon/cmd/goabi-gen

package tracing

import (
	"errors"
	"fmt"
	"runtime"
	"strings"

	"github.com/cilium/tetragon/pkg/asm"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
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

// GoABISlotRegNames returns the ptr and len register names for a Go string at slot.
func GoABISlotRegNames(slot int) (ptrReg, lenReg string, err error) {
	if !archHasGoString() {
		return "", "", errGoStringUnsupportedArch()
	}
	if slot < 0 || slot+1 >= len(goABIIntRegs) {
		return "", "", fmt.Errorf("go ABI slot %d out of range (max %d for string)", slot, len(goABIIntRegs)-2)
	}
	return goABIIntRegs[slot], goABIIntRegs[slot+1], nil
}

// expandClearGoStringActions turns clearGoString into a plain Override on the
// Go string's len register so the selector layer just sees argRegs.
func expandClearGoStringActions(spec *v1alpha1.UProbeSpec) error {
	for si := range spec.Selectors {
		sel := &spec.Selectors[si]
		for ai := range sel.MatchActions {
			act := &sel.MatchActions[ai]
			if !act.ClearGoString {
				continue
			}
			if !strings.EqualFold(act.Action, "Override") {
				return errors.New("clearGoString is only valid with action Override")
			}
			if len(act.ArgRegs) > 0 {
				return errors.New("clearGoString cannot be combined with argRegs")
			}
			if len(spec.Symbols) != 1 {
				return errors.New("clearGoString requires exactly one uprobe symbol")
			}
			sym := spec.Symbols[0]
			slot := GoABISlotForArg(sym, int(act.ArgIndex))
			if slot < 0 {
				return fmt.Errorf("clearGoString: unknown Go ABI layout for %s arg %d", sym, act.ArgIndex)
			}
			_, lenReg, err := GoABISlotRegNames(slot)
			if err != nil {
				return fmt.Errorf("clearGoString: %w", err)
			}
			act.ArgRegs = []string{lenReg + "=0"}
			act.ClearGoString = false
		}
	}
	return nil
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
