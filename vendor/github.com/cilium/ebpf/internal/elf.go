package internal

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

// Symbols is the safe version of elf.File.Symbols.
func (se *SafeELFFile) Symbols() (syms []elf.Symbol, err error) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}

		syms = nil
		err = fmt.Errorf("reading ELF symbols panicked: %s", r)
	}()

	syms, err = se.File.Symbols()
	return
}

// DynamicSymbols is the safe version of elf.File.DynamicSymbols.
func (se *SafeELFFile) DynamicSymbols() (syms []elf.Symbol, err error) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}

		syms = nil
		err = fmt.Errorf("reading ELF dynamic symbols panicked: %s", r)
	}()

	syms, err = se.File.DynamicSymbols()
	return
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
