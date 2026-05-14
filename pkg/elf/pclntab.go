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
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
)

const (
	secGopclntab    = ".gopclntab"
	secGopclntabPIE = ".data.rel.ro.gopclntab"
	secSymtab       = ".symtab"
)

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

func (se *SafeELFFile) IsStrippedPureGoBinary() bool {
	hasPclntab := se.Section(secGopclntab) != nil || se.Section(secGopclntabPIE) != nil
	hasSymtab := se.Section(secSymtab) != nil
	return hasPclntab && !hasSymtab && !isCgo(se.File)
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

// Returns the ABI-deduped file offset for the named function
func (t *GoPclntab) OffsetByName(name string) (uint64, bool) {
	fn, ok := t.byName[name]
	if !ok {
		return 0, false
	}
	return fn.Offset, true
}

func isCgo(f *elf.File) bool {
	// Pure Go binaries use cmd/link which does not emit .plt/.init sections
	return f.Section(".plt") != nil || f.Section(".init") != nil
}

// Converts .gopclntab into a GoPclntab of function names and file offsets,
// used by Pclntab() on initial open of file
func (se *SafeELFFile) extractUprobeOffsets() (*GoPclntab, error) {
	table, err := pclntabToGosymtab(se.File)
	if err != nil {
		return nil, err
	}

	funcs := make([]UprobeOffset, 0, len(table.Funcs))
	for _, fn := range table.Funcs {
		funcs = append(funcs, UprobeOffset{
			Name:   fn.Name,
			Offset: pclntabVAToFileOffset(se.File, fn.Entry),
			End:    pclntabVAToFileOffset(se.File, fn.End),
		})
	}
	sort.Slice(funcs, func(i, j int) bool {
		return funcs[i].Offset < funcs[j].Offset
	})

	// When Go emits multiple pclntab entries for the same name
	// (ABIInternal + ABI0 wrapper), keep the largest function
	// which is he real implementation, not the wrapper
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

// Parses .gopclntab into a gosym.Table anchored at the text base.
// Used by extractUprobeOffsets()
func pclntabToGosymtab(f *elf.File) (*gosym.Table, error) {
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

	if err := pclntabRejectPreGo126(pclntab); err != nil {
		return nil, err
	}

	textStart, err := pclntabResolveTextStart(f)
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

// ValidateGoABI checks that the binary uses a Go ABI compatible with the
// static register slot table. Works on both stripped and unstripped binaries.
func (se *SafeELFFile) ValidateGoABI() error {
	pclnSect := se.Section(secGopclntab)
	if pclnSect == nil {
		pclnSect = se.Section(secGopclntabPIE)
	}
	if pclnSect == nil {
		return fmt.Errorf("no %s section: not a Go binary", secGopclntab)
	}
	data, err := pclnSect.Data()
	if err != nil {
		return fmt.Errorf("read %s: %w", secGopclntab, err)
	}
	return pclntabRejectPreGo126(data)
}

// Rejects binaries compiled before Go 1.26 by checking whether the
// pclntab header's textStart field is zero (zeroed in Go 1.26+, see
// https://github.com/golang/go/commit/0e1bd8b5f17e337df0ffb57af03419b96c695fe4)
func pclntabRejectPreGo126(pclntab []byte) error {
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
func pclntabResolveTextStart(f *elf.File) (uint64, error) {
	if isCgo(f) {
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
