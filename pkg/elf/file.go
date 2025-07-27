// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// Borrowed from https://github.com/cilium/ebpf/ thanks! ;-)

package elf

import (
	"debug/elf"
	"fmt"
	"io"
)

type SafeELFFile struct {
	*elf.File
}

// NewSafeELFFile reads an ELF safely.
//
// Any panic during parsing is turned into an error. This is necessary since
// there are a bunch of unfixed bugs in debug/elf.
//
// https://github.com/golang/go/issues?q=is%3Aissue+is%3Aopen+debug%2Felf+in%3Atitle
func NewSafeELFFile(r io.ReaderAt) (safe *SafeELFFile, err error) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}

		safe = nil
		err = fmt.Errorf("reading ELF file panicked: %s", r)
	}()

	file, err := elf.NewFile(r)
	if err != nil {
		return nil, err
	}

	return &SafeELFFile{file}, nil
}

// OpenSafeELFFile reads an ELF from a file.
//
// It works like NewSafeELFFile, with the exception that safe.Close will
// close the underlying file.
func OpenSafeELFFile(path string) (safe *SafeELFFile, err error) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}

		safe = nil
		err = fmt.Errorf("reading ELF file panicked: %s", r)
	}()

	file, err := elf.Open(path)
	if err != nil {
		return nil, err
	}

	return &SafeELFFile{file}, nil
}

func (se *SafeELFFile) Offset(name string) (uint64, error) {
	symbols, err := se.Symbols()
	if err != nil {
		return 0, err
	}

	for _, sym := range symbols {
		if elf.ST_TYPE(sym.Info) != elf.STT_FUNC {
			continue
		}

		if name != sym.Name {
			continue
		}

		offset := sym.Value

		// Loop over ELF segments.
		for _, prog := range se.Progs {
			// Skip uninteresting segments.
			if prog.Type != elf.PT_LOAD || (prog.Flags&elf.PF_X) == 0 {
				continue
			}

			if prog.Vaddr <= sym.Value && sym.Value < (prog.Vaddr+prog.Memsz) {
				// If the symbol value is contained in the segment, calculate
				// the symbol offset.
				//
				// fn symbol offset = fn symbol VA - .text VA + .text offset
				//
				// stackoverflow.com/a/40249502
				offset = sym.Value - prog.Vaddr + prog.Off
				break
			}
		}
		return offset, nil
	}

	return 0, fmt.Errorf("symbol not found %s", name)
}

// SectionsByType returns all sections in the file with the specified section type.
func (se *SafeELFFile) SectionsByType(typ elf.SectionType) []*elf.Section {
	sections := make([]*elf.Section, 0, 1)
	for _, section := range se.Sections {
		if section.Type == typ {
			sections = append(sections, section)
		}
	}
	return sections
}

// SectionsByName returns all sections in the file with the specified section name.
func (se *SafeELFFile) SectionsByName(name string) []*elf.Section {
	sections := make([]*elf.Section, 0, 1)
	for _, section := range se.Sections {
		if section.Name == name {
			sections = append(sections, section)
		}
	}
	return sections
}

// ProgByVaddr returns elf program header for the specified vaddr.
func (se *SafeELFFile) ProgByVaddr(vaddr uint64) *elf.Prog {
	for _, prog := range se.Progs {
		if (prog.Vaddr <= vaddr) && (vaddr < (prog.Vaddr + prog.Memsz)) {
			return prog
		}
	}
	return nil
}
