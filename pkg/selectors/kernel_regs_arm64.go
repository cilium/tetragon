// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build arm64 && linux

package selectors

import "errors"

func parseOverrideRegs(k *KernelSelectorState, values []string, errValue uint64) (uint32, error) {
	return uint32(0xffffffff), errors.New("register override is not supported")
}
