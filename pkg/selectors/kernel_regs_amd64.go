// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build amd64 && linux

package selectors

import (
	"errors"
	"fmt"

	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/asm"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

const ArgsInRegisters = 6 // Number of arguments passed by register per System V AMD64 ABI

var argIndexRegisters = [ArgsInRegisters]string{"rdi", "rsi", "rdx", "rcx", "r8", "r9"}

func ArgIndexRegister(argIndex uint32) string {
	return argIndexRegisters[argIndex]
}

func parseOverrideRegs(k *KernelSelectorState, selIdx int, values []string, errValue uint64, newOffset int64, args []v1alpha1.KProbeArg, data []v1alpha1.KProbeArg) error {
	if _, exists := k.regs[selIdx]; exists {
		return errors.New("only single instance of regs action is allowed")
	}

	regs := []processapi.RegAssignment{}

	if newOffset != 0 {
		values = append(values, fmt.Sprintf("rip=%d%%rip", newOffset))
	}

	// If no registers were specified go with the default for override
	// at the top of the user space function.
	if len(values) == 0 {
		values = []string{
			fmt.Sprintf("rax=%d", errValue),
			"rip=(%rsp)",
			"rsp=8%rsp",
		}
	}

	for _, val := range values {
		reg, expr, found := cutCelAssignment(val)

		if found {
			ass, err := parseCelAssignment(k, reg, expr, args, data)
			if err != nil {
				return err
			}
			regs = append(regs, ass)
			continue
		}

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

func parseSetRegs(k *KernelSelectorState, selIdx int, argIndex uint32, argValue uint64) error {
	val := fmt.Sprintf("%s=%d", ArgIndexRegister(argIndex), argValue)

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
