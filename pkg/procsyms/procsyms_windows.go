// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package procsyms

import (
	"errors"
)

// GetFnSymbol -- returns the FnSym for a given address and PID
func GetFnSymbol(pid int, addr uint64) (*FnSym, error) {
	return nil, errors.New("not implemented on windows ")

}
