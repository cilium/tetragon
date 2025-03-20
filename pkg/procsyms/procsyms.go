// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package procsyms

import (
	"fmt"
)

// FnSym is a function location (function name, module path + offset)
type FnSym struct {
	Name   string
	Module string
	Offset uint64
}

// ToString returns a string representation of FnSym
func (fsym *FnSym) ToString() string {
	return fmt.Sprintf("%s (%s+0x%x)", fsym.Name, fsym.Module, fsym.Offset)
}
