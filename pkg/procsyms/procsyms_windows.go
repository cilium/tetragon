// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package procsyms

import (
	"github.com/cilium/tetragon/pkg/constants"
)

// GetFnSymbol -- returns the FnSym for a given address and PID
func GetFnSymbol(_ int, _ uint64) (*FnSym, error) {
	return nil, constants.ErrWindowsNotSupported
}
