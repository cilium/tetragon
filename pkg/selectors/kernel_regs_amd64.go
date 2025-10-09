// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build amd64 && linux
// +build amd64,linux

package selectors

import (
	"errors"

	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/asm"
)

func parseOverrideRegs(k *KernelSelectorState, values []string) (uint32, error) {
	if len(k.regs) > 0 {
		return uint32(0xffffffff), errors.New("only single instance of regs action is allowed")
	}

	regs := []processapi.RegAssignment{}

	for _, val := range values {
		ass, err := asm.ParseAssignment(val)
		if err != nil {
			return uint32(0xffffffff), err
		}

		regs = append(regs, processapi.RegAssignment{
			Type: ass.Type,
			Src:  ass.Src,
			Dst:  ass.Dst,
			Off:  ass.Off,
		})
	}

	k.regs = regs
	return uint32(0), nil
}
