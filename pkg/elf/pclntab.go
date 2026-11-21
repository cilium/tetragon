// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// Pclntab support: parses Go's .gopclntab ELF section to resolve function
// symbols in stripped Go binaries. The Go runtime embeds a Program Counter
// Line Table that survives stripping because the runtime itself depends on
// it for stack traces and panic output.
//
// The following is a sample line table (values from node_exporter-unstripped):
//
//	0x401000   "runtime.text"
//	0x456640   "runtime.main"
//	0x4579a0   "runtime.schedinit"
//	...
//	0xabf880   "main.main"
//
// The methods here convert those vaddrs to file offsets via PT_LOAD
// segments so they can be used directly for uprobe attachment:
//
//	pclntab entry:  0x456640 -> "runtime.main"
//	PT_LOAD:        vaddr 0x400000, offset 0x0
//	uprobe offset:  0x456640 - 0x400000 + 0x0 = 0x56640

package elf

import (
	"debug/elf"
	"debug/gosym"
	"errors"
	"fmt"
	"slices"
	"sort"
)

const (
	secGopclntab    = ".gopclntab"
	secGopclntabPIE = ".data.rel.ro.gopclntab"
	secDataRelRo    = ".data.rel.ro"
	secGoBuildinfo  = ".go.buildinfo"
	secSymtab       = ".symtab"
	secText         = ".text"
	secGoModule     = ".go.module"
	secNoptrdata    = ".noptrdata"

	moduledataTextWord = 22
)

// Go 1.18 and Go 1.20+ pclntab header magics
var pclntabMagics = []uint32{0xfffffff0, 0xfffffff1}

// External linkers before Go 1.26 merge .gopclntab into .data.rel.ro
var pclntabSections = []string{secGopclntab, secGopclntabPIE, secDataRelRo}

type UprobeOffset struct {
	Name   string
	Offset uint64
	End    uint64
}

// Holds parsed .gopclntab uprobe offsets for a Go binary
type GoPclntab struct {
	funcs  []UprobeOffset
	byName map[string]UprobeOffset // deduplicated: largest function per name
}

// .go.buildinfo survives stripping and external linking, unlike .gopclntab
func (se *SafeELFFile) IsStrippedGoBinary() bool {
	return se.Section(secGoBuildinfo) != nil && se.Section(secSymtab) == nil
}

// Parses .gopclntab and returns a GoPclntab of function offsets,
// which can then be queried by name for uprobe attachment
func (se *SafeELFFile) Pclntab() (*GoPclntab, error) {
	se.pclntabOnce.Do(func() {
		se.pclntab, se.pclntabErr = se.extractUprobeOffsets()
	})
	return se.pclntab, se.pclntabErr
}

// Returns all function symbols sorted by file offset
func (t *GoPclntab) AllFuncs() []UprobeOffset {
	out := make([]UprobeOffset, len(t.funcs))
	copy(out, t.funcs)
	return out
}

// Returns the file offset of name in a stripped Go binary: Go functions
// through .gopclntab and the rest, such as cgo's C functions, through .dynsym.
// A .gopclntab that does not parse, such as one from before Go 1.18, still
// resolves C functions.
func (se *SafeELFFile) StrippedGoOffset(name string) (uint64, error) {
	tbl, err := se.Pclntab()
	if err == nil {
		if off, ok := tbl.OffsetByName(name); ok {
			return off, nil
		}
	}
	// Undefined .dynsym entries (library imports) have address 0
	if addr, dynErr := se.DynamicAddress(name); dynErr == nil && addr != 0 {
		return se.OffsetFromAddr(addr)
	}
	if err != nil {
		return 0, fmt.Errorf("%q not in .dynsym (.gopclntab: %w)", name, err)
	}
	return 0, fmt.Errorf("%q in neither .gopclntab nor .dynsym", name)
}

// Returns the ABI-deduped file offset for the named function
func (t *GoPclntab) OffsetByName(name string) (uint64, bool) {
	fn, ok := t.byName[name]
	if !ok {
		return 0, false
	}
	return fn.Offset, true
}

// Converts .gopclntab into a GoPclntab of function names and file offsets,
// used by Pclntab() on initial open of file
func (se *SafeELFFile) extractUprobeOffsets() (*GoPclntab, error) {
	table, text, err := pclntabFuncs(se.File)
	if err != nil {
		return nil, err
	}

	funcs := make([]UprobeOffset, 0, len(table.Funcs))
	for _, fn := range table.Funcs {
		funcs = append(funcs, UprobeOffset{
			Name:   fn.Name,
			Offset: pclntabVAToFileOffset(se.File, text+fn.Entry),
			End:    pclntabVAToFileOffset(se.File, text+fn.End),
		})
	}
	sort.Slice(funcs, func(i, j int) bool {
		return funcs[i].Offset < funcs[j].Offset
	})

	// When Go emits multiple pclntab entries for the same name
	// (ABIInternal + ABI0 wrapper), keep the largest function
	// which is the real implementation, not the wrapper
	byName := make(map[string]UprobeOffset, len(funcs))
	bestSize := make(map[string]uint64, len(funcs))
	for _, fn := range funcs {
		size := fn.End - fn.Offset
		if bestSize[fn.Name] >= size {
			continue
		}
		byName[fn.Name] = fn
		bestSize[fn.Name] = size
	}

	return &GoPclntab{funcs: funcs, byName: byName}, nil
}

// Parses .gopclntab whose function entries are offset from runtime.text.
// Returns the runtime.text read from the runtime's moduledata.
func pclntabFuncs(f *elf.File) (*gosym.Table, uint64, error) {
	var pclnSect *elf.Section
	for _, name := range pclntabSections {
		if pclnSect = f.Section(name); pclnSect != nil {
			break
		}
	}
	if pclnSect == nil {
		return nil, 0, fmt.Errorf("no %s section: not a Go binary", secGopclntab)
	}
	textSect := f.Section(secText)
	if textSect == nil {
		return nil, 0, errors.New("no .text section")
	}

	pclntab, err := pclnSect.Data()
	if err != nil {
		return nil, 0, fmt.Errorf("read %s: %w", pclnSect.Name, err)
	}

	hdr, text, ok := moduledata(f, pclnSect, pclntab, textSect)
	if !ok {
		return nil, 0, errors.New("runtime moduledata not found: Go 1.18+ required")
	}
	table, err := gosym.NewTable(nil, gosym.NewLineTable(pclntab[hdr-pclnSect.Addr:], 0))
	if err != nil {
		return nil, 0, fmt.Errorf("parse pclntab: %w", err)
	}
	return table, text, nil
}

// Locates firstmoduledata (.go.module on Go 1.26+, else .noptrdata) and
// returns its pcHeader and runtime.text. Scan for a pcHeader pointing at a
// pclntab magic in pcln, funcnametab after it, and runtime.text in .text.
// Words are pointer-sized:
//
//	 0 (pcHeader)   1 (funcnametab)        22 (text)              .text
//	+------------+--------------+- ... -+-------------+         +-------------+
//	| -> magic   | > pcHeader   |       | runtime.text|---------| start of Go |
//	+------------+--------------+- ... -+-------------+         +-------------+
func moduledata(f *elf.File, pcln *elf.Section, pclntab []byte, text *elf.Section) (hdr, rtext uint64, ok bool) {
	within := func(s *elf.Section, v uint64) bool { return v >= s.Addr && v < s.Addr+s.Size }
	isPcHeader := func(v uint64) bool {
		off := v - pcln.Addr
		return within(pcln, v) && off+4 <= uint64(len(pclntab)) &&
			slices.Contains(pclntabMagics, f.ByteOrder.Uint32(pclntab[off:]))
	}
	for _, name := range []string{secGoModule, secNoptrdata} {
		sect := f.Section(name)
		if sect == nil || sect.Type != elf.SHT_PROGBITS {
			continue
		}
		data, err := sect.Data()
		if err != nil {
			continue
		}
		size, word := 8, func(i int) uint64 { return f.ByteOrder.Uint64(data[i*8:]) }
		if f.Class == elf.ELFCLASS32 {
			size, word = 4, func(i int) uint64 { return uint64(f.ByteOrder.Uint32(data[i*4:])) }
		}
		for i := 0; i+moduledataTextWord < len(data)/size; i++ {
			hdr, rtext = word(i), word(i+moduledataTextWord)
			if within(text, rtext) && isPcHeader(hdr) && word(i+1) > hdr && within(pcln, word(i+1)) {
				return hdr, rtext, true
			}
		}
	}
	return 0, 0, false
}

// Converts a vaddr to a file offset via the executable PT_LOAD segment:
// file_offset = va - pt_load.Vaddr + pt_load.Off
func pclntabVAToFileOffset(f *elf.File, va uint64) uint64 {
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD && (p.Flags&elf.PF_X) != 0 {
			if va >= p.Vaddr && va < p.Vaddr+p.Memsz {
				return va - p.Vaddr + p.Off
			}
		}
	}
	return va
}
