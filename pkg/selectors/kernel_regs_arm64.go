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

func parseOverrideRegs(k *KernelSelectorState, values []string, errValue uint64) (uint32, error) {
	if len(k.regs) > 0 {
		return uint32(0xffffffff), errors.New("only single instance of regs action is allowed")
	}

	regs := []processapi.RegAssignment{}

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
			return uint32(0xffffffff), err
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

	k.regs = regs
	return uint32(0), nil
}
