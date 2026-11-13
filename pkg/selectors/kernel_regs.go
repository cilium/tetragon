// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux && (amd64 || arm64)

package selectors

import (
	"fmt"
	"strings"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

func OverrideWrittenRegs(action v1alpha1.ActionSelector) ([]string, error) {
	var regs []string

	// Get the left hand side of any explicit register overrides
	for _, val := range action.ArgRegs {
		dst, _, found := strings.Cut(val, "=")
		if !found {
			return nil, fmt.Errorf("failed to parse register assignment '%s'", val)
		}

		regs = append(regs, strings.TrimSpace(dst))
	}

	// Add the ip register to the list if execution is redirected
	if action.ArgNewSymbol != "" || action.ArgNewAddr != 0 || action.ArgNewOffset != 0 {
		regs = append(regs, overrideIPReg)
	}

	// Last possible configuration is when a function returns a defined value
	// without running the actual code
	if len(regs) == 0 {
		regs = append(regs, defaultOverrideRegs...)
	}

	return regs, nil
}
