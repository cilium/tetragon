// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build arm64 && linux

package selectors

import (
	"errors"
	"fmt"

	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/asm"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

const ArgsInRegisters = 8 // Number of arguments passed by register per AArch64 ABI

func parseOverrideRegs(k *KernelSelectorState, selIdx int, values []string, errValue uint64, newOffset int64, args []v1alpha1.KProbeArg, data []v1alpha1.KProbeArg) error {
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
		reg, expr, found, err := asm.CutCelAssignment(val)
		if err != nil {
			return err
		}

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

func parseCelAssignment(k *KernelSelectorState, reg, expr string,
	args, data []v1alpha1.KProbeArg) (processapi.RegAssignment, error) {

	if reg == "" {
		return processapi.RegAssignment{},
			fmt.Errorf("cel assignment has no destination register: 'cel(%s)'", expr)
	}

	dst, dstSize, ok := asm.RegOffsetSize(reg)
	if !ok {
		return processapi.RegAssignment{},
			fmt.Errorf("failed to parse register '%s'", reg)
	}

	idx, err := addRegCelExpr(k.CelExprFunctions(), expr, args, data)
	if err != nil {
		return processapi.RegAssignment{}, err
	}

	return processapi.RegAssignment{
		Type:    asm.ASM_ASSIGNMENT_TYPE_CEL,
		Dst:     dst,
		DstSize: dstSize,
		Off:     uint64(idx),
		// Src/SrcSize stay zero — there is no single source register.
	}, nil
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
