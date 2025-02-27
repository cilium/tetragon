// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package procsyms

import (
	"fmt"
	"sync"

	lru "github.com/hashicorp/golang-lru/v2"
)

var (
	cache *lru.Cache[struct {
		module string
		offset uint64
	}, string]
	setCache sync.Once
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

// GetFnSymbol -- returns the FnSym for a given address and PID
func GetFnSymbol(pid int, addr uint64) (*FnSym, error) {
	return nil, fmt.Errorf("not implemented on windows (yet) ")

}
