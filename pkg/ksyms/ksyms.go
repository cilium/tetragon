// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package ksyms

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/cilium/tetragon/pkg/logger"

	lru "github.com/hashicorp/golang-lru/v2"
)

type ksym struct {
	addr uint64
	name string
	ty   string
}

// Ksyms is a structure for kernel symbols
type Ksyms struct {
	table   []ksym
	fnCache *lru.Cache[uint64, fnOffsetVal]
}

// FnOffset is a function location (function name + offset)
type FnOffset struct {
	SymName string
	Offset  uint64
}

// fnOffsetVal is used as a value in the FnOffset cache.
type fnOffsetVal struct {
	fnOffset *FnOffset
	err      error
}

// ToString returns a string representation of FnOffset
func (fo *FnOffset) ToString() string {
	return fmt.Sprintf("%s()+0x%x", fo.SymName, fo.Offset)
}

func (ksym *ksym) isFunction() bool {
	tyLow := strings.ToLower(ksym.ty)
	return tyLow == "w" || tyLow == "t"
}

// NewKsyms creates a new Ksyms structure (by reading procfs/kallsyms)
func NewKsyms(procfs string) (*Ksyms, error) {
	kallsymsFname := fmt.Sprintf("%s/kallsyms", procfs)
	file, err := os.Open(kallsymsFname)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	err = nil
	var ksyms Ksyms
	s := bufio.NewScanner(file)
	needsSort := false

	for s.Scan() {
		txt := s.Text()
		fields := strings.Fields(txt)
		var sym ksym

		if len(fields) < 3 {
			fmt.Fprintf(os.Stderr, "Failed to parse: '%s'\n", txt)
			continue
		}

		if sym.addr, err = strconv.ParseUint(fields[0], 16, 64); err != nil {
			err = fmt.Errorf("failed to parse address: %v", err)
			break
		}
		sym.ty = fields[1]
		sym.name = fields[2]

		//fmt.Printf("%s => %d %s\n", txt, sym.addr, sym.name)
		if sym.isFunction() && sym.addr == 0 {
			err = fmt.Errorf("function %s reported at address 0. Insuffcient permissions?", sym.name)
			break
		}

		if !needsSort && len(ksyms.table) > 0 {
			lastSym := ksyms.table[len(ksyms.table)-1]
			if lastSym.addr > sym.addr {
				needsSort = true
			}
		}

		ksyms.table = append(ksyms.table, sym)
	}

	if err == nil {
		err = s.Err()
	}

	if err != nil && len(ksyms.table) == 0 {
		err = errors.New("No synmbols found")
	}

	if err != nil {
		return nil, err
	}

	if needsSort {
		sort.Slice(ksyms.table[:], func(i1, i2 int) bool { return ksyms.table[i1].addr < ksyms.table[i2].addr })
	}

	fc, err := lru.New[uint64, fnOffsetVal](1024)
	if err == nil {
		ksyms.fnCache = fc
	} else {

		logger.GetLogger().Infof("failed to initialize cache: %s", err)
	}

	return &ksyms, nil
}

// GetFnOffset -- returns the FnOffset for a given address
func (k *Ksyms) GetFnOffset(addr uint64) (*FnOffset, error) {
	// no cache
	if k.fnCache == nil {
		return k.getFnOffset(addr)
	}

	// cache hit
	if ret, ok := k.fnCache.Get(addr); ok {
		return ret.fnOffset, ret.err
	}

	// cache miss
	fnOffset, err := k.getFnOffset(addr)
	k.fnCache.Add(addr, fnOffsetVal{fnOffset: fnOffset, err: err})
	return fnOffset, err

}

// GetFnOffset -- retruns the FnOffset for a given address
func (k *Ksyms) getFnOffset(addr uint64) (*FnOffset, error) {
	// address is before first symbol
	if k.table[0].addr > addr {
		return nil, fmt.Errorf("address %d is before first symbol %s@%d", addr, k.table[0].name, k.table[0].addr)
	}

	// binary search
	l, r := 0, len(k.table)-1

	for l < r {
		// prevents overflow
		m := l + ((r - l + 1) >> 1)
		if k.table[m].addr < addr {
			l = m
		} else {
			r = m - 1
		}
	}

	sym := k.table[l]
	if !sym.isFunction() {
		return nil, fmt.Errorf("Unable to find function for addr 0x%x", addr)
	}

	return &FnOffset{
		SymName: sym.name,
		Offset:  addr - sym.addr,
	}, nil
}
