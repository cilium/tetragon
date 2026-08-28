// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build arm64 && linux

package selectors

import (
	"errors"
	"fmt"

	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/asm"
)

const ArgsInRegisters = 8 // Number of arguments passed by register per AArch64 ABI

func parseOverrideRegs(k *KernelSelectorState, selIdx int, values []string, errValue uint64, newOffset int64) error {
	if _, exists := k.regs[selIdx]; exists {
		return errors.New("only single instance of regs action is allowed")
	}

	regs := []processapi.RegAssignment{}

	if newOffset != 0 {
		values = append(values, fmt.Sprintf("pc=%d%%pc", newOffset))
	}

	// If no registers were specified go with the default for override
	// at the top of the user space function.
	if len(values) == 0 {
		values = []string{
			fmt.Sprintf("x0=%d", errValue),
			"pc=%x30",
		}
	}

	for _, val := range values {
		ass, err := asm.ParseAssignment(val)
		if err != nil {
			return err
		}

		regs = append(regs, processapi.RegAssignment{
			Type:    ass.Type,
			Src:     ass.Src,
			Dst:     ass.Dst,
			SrcSize: ass.SrcSize,
			DstSize: ass.DstSize,
			Off:     ass.Off,
		})
	}

	k.regs[selIdx] = regs
	return nil
}

func parseSetRegs(k *KernelSelectorState, selIdx int, argIndex, argValue uint32) error {
	val := fmt.Sprintf("x%d=%d", argIndex, argValue)

	ass, err := asm.ParseAssignment(val)
	if err != nil {
		return err
	}

	reg := processapi.RegAssignment{
		Type:    ass.Type,
		Src:     ass.Src,
		Dst:     ass.Dst,
		SrcSize: ass.SrcSize,
		DstSize: ass.DstSize,
		Off:     ass.Off,
	}

	k.regs[selIdx] = append(k.regs[selIdx], reg)
	return nil
}
