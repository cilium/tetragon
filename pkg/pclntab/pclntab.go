// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// Package pclntab parses Go's .gopclntab ELF section to resolve function
// symbols in stripped Go binaries -- the Go runtime embeds a Program Counter
// Line Table that survives stripping because the runtime itself depends on
// it for stack traces and panic output
//
// The .gopclntab section maps program counters to function names
// (values below from testdata/node_exporter-unstripped):
//
//	0x401000   "runtime.text"
//	0x456640   "runtime.main"
//	0x4579a0   "runtime.schedinit"
//	...
//	0xabf880   "main.main"
//
// This package converts those vaddrs to file offsets via PT_LOAD
// segments so they can be used directly for uprobe attachment:
//
//	pclntab entry:  0x456640 -> "runtime.main"
//	PT_LOAD:        vaddr 0x400000, offset 0x0
//	uprobe offset:  0x456640 - 0x400000 + 0x0 = 0x56640
package pclntab

import (
	"debug/elf"
	"debug/gosym"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"sync"
)

const (
	secGopclntab    = ".gopclntab"
	secGopclntabPIE = ".data.rel.ro.gopclntab"
	secSymtab       = ".symtab"
)

type FuncOffset struct {
	Name   string
	Offset uint64
	End    uint64
}

// Table containing function offsets and an ABI-deduplicated view of symbols
type offsetTable struct {
	funcs  []FuncOffset
	byName map[string]FuncOffset // deduplicated: largest function per name
}

var (
	mu          sync.RWMutex
	offsetCache = make(map[string]*offsetTable)
)

// Parses .gopclntab for path into an offset table, caching per binary path
func loadOffsetsFromTable(path string) (*offsetTable, error) {
	mu.RLock()
	idx, ok := offsetCache[path]
	mu.RUnlock()
	if ok {
		return idx, nil
	}

	f, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open ELF: %w", err)
	}
	defer f.Close()

	table, err := buildSymTable(f)
	if err != nil {
		return nil, err
	}

	// Build FuncOffset slice with file offsets suitable for uprobe attachment
	funcs := make([]FuncOffset, 0, len(table.Funcs))
	for _, fn := range table.Funcs {
		funcs = append(funcs, FuncOffset{
			Name:   fn.Name,
			Offset: vaToFileOffset(f, fn.Entry),
			End:    vaToFileOffset(f, fn.End),
		})
	}
	// Sort by file offset for stable, ordered output
	sort.Slice(funcs, func(i, j int) bool {
		return funcs[i].Offset < funcs[j].Offset
	})

	// Build deduplicated name->FuncOffset map; when Go emits multiple
	// pclntab entries for the same name (ABIInternal + ABI0 wrapper),
	// keep the largest function -- the real implementation, not the
	// thin ABI0 shim
	byName := make(map[string]FuncOffset, len(funcs))
	bestSize := make(map[string]uint64, len(funcs))
	for _, fn := range funcs {
		size := fn.End - fn.Offset
		if bestSize[fn.Name] >= size {
			continue
		}
		byName[fn.Name] = fn
		bestSize[fn.Name] = size
	}

	idx = &offsetTable{funcs: funcs, byName: byName}
	mu.Lock()
	offsetCache[path] = idx
	mu.Unlock()
	return idx, nil
}

// Returns all function symbols from a Go binary's .gopclntab; used by "tetra generate uprobes"
func AllFuncs(path string) ([]FuncOffset, error) {
	ot, err := loadOffsetsFromTable(path)
	if err != nil {
		return nil, err
	}
	out := make([]FuncOffset, len(ot.funcs))
	copy(out, ot.funcs)
	return out, nil
}

// Resolves the given symbol names to deduplicated FuncOffsets via .gopclntab
func Lookup(path string, names []string) ([]FuncOffset, error) {
	ot, err := loadOffsetsFromTable(path)
	if err != nil {
		return nil, err
	}

	var out []FuncOffset
	for _, name := range names {
		if fn, ok := ot.byName[name]; ok {
			out = append(out, fn)
		}
	}
	return out, nil
}

func IsStrippedGoBinary(path string) bool {
	f, err := elf.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	hasPclntab := f.Section(secGopclntab) != nil || f.Section(secGopclntabPIE) != nil
	hasSymtab := f.Section(secSymtab) != nil
	return hasPclntab && !hasSymtab
}

// Parses .gopclntab into a gosym.Table anchored at the text base
func buildSymTable(f *elf.File) (*gosym.Table, error) {
	// Try standard section first, then PIE layout
	pclnSect := f.Section(secGopclntab)
	if pclnSect == nil {
		pclnSect = f.Section(secGopclntabPIE)
	}
	if pclnSect == nil {
		return nil, fmt.Errorf("no %s section: not a Go binary", secGopclntab)
	}

	pclntab, err := pclnSect.Data()
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", secGopclntab, err)
	}

	if err := rejectPreGo126(pclntab); err != nil {
		return nil, err
	}

	textStart, err := resolveTextStart(f)
	if err != nil {
		return nil, err
	}

	lineTable := gosym.NewLineTable(pclntab, textStart)
	table, err := gosym.NewTable(nil, lineTable)
	if err != nil {
		return nil, fmt.Errorf("parse pclntab: %w", err)
	}
	return table, nil
}

// Rejects binaries compiled before Go 1.26 by checking whether the
// pclntab header's textStart field is zero (zeroed in Go 1.26+, see
// https://github.com/golang/go/commit/0e1bd8b5f17e337df0ffb57af03419b96c695fe4)
func rejectPreGo126(pclntab []byte) error {
	//  0       4     6   7   8       8+P     8+2P
	// +-------+-----+---+---+-------+-------+-----------+
	// | magic | pad |mLC|psz| nfunc | nfiles| textStart |
	// |  (4)  | (2) |(1)|(1)|  (P)  |  (P)  |    (P)    |
	// +-------+-----+---+---+-------+-------+-----------+
	// P = ptrSize (4 or 8); textStart is zero for Go 1.26+
	if len(pclntab) < 8 {
		return errors.New("pclntab too short")
	}
	ptrSize := int(pclntab[7])
	if ptrSize != 4 && ptrSize != 8 {
		return fmt.Errorf("unexpected ptrSize %d", ptrSize)
	}
	off := 8 + 2*ptrSize
	if len(pclntab) < off+ptrSize {
		return errors.New("pclntab header truncated")
	}
	var textStart uint64
	if ptrSize == 8 {
		textStart = binary.LittleEndian.Uint64(pclntab[off:])
	} else {
		textStart = uint64(binary.LittleEndian.Uint32(pclntab[off:]))
	}
	if textStart != 0 {
		return errors.New("pre-Go 1.26 binary (textStart != 0)")
	}
	return nil
}

// Returns the .text section vaddr for pure-Go binaries
func resolveTextStart(f *elf.File) (uint64, error) {
	// ignore CGo binaries
	if f.Section(".plt") != nil || f.Section(".init") != nil {
		return 0, errors.New("CGo binaries not supported")
	}

	// .text vaddr == runtime.text for pure-Go binaries
	textSect := f.Section(".text")
	if textSect == nil {
		return 0, errors.New("no .text section")
	}
	return textSect.Addr, nil
}

// Converts a vaddr to a file offset via the executable PT_LOAD segment:
// file_offset = va - pt_load.Vaddr + pt_load.Off
func vaToFileOffset(f *elf.File, va uint64) uint64 {
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD && (p.Flags&elf.PF_X) != 0 {
			if va >= p.Vaddr && va < p.Vaddr+p.Memsz {
				return va - p.Vaddr + p.Off
			}
		}
	}
	return va
}
