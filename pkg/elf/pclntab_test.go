// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux

package elf

import (
	"debug/elf"
	"os"
	"slices"
	"testing"

	"github.com/cilium/tetragon/pkg/testutils"
)

func pclntabSkipIfNoBins(t *testing.T) (stripped, unstripped string) {
	t.Helper()
	stripped = testutils.RepoRootPath("contrib/tester-progs/pclntab-stripped")
	unstripped = testutils.RepoRootPath("contrib/tester-progs/pclntab-unstripped")
	if _, err := os.Stat(stripped); err != nil {
		t.Skipf("pclntab-stripped not found: %v", err)
	}
	if _, err := os.Stat(unstripped); err != nil {
		t.Skipf("pclntab-unstripped not found: %v", err)
	}
	return stripped, unstripped
}

func openSafe(t *testing.T, path string) *SafeELFFile {
	t.Helper()
	f, err := OpenSafeELFFile(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func TestIsStrippedPureGoBinary(t *testing.T) {
	stripped, unstripped := pclntabSkipIfNoBins(t)

	if !openSafe(t, stripped).IsStrippedPureGoBinary() {
		t.Fatal("expected stripped binary to be detected as stripped Go binary")
	}
	if openSafe(t, unstripped).IsStrippedPureGoBinary() {
		t.Fatal("expected unstripped binary to NOT be detected as stripped")
	}
	if f, err := OpenSafeELFFile("/bin/sh"); err == nil {
		defer f.Close()
		if f.IsStrippedPureGoBinary() {
			t.Fatal("expected /bin/sh to NOT be detected as stripped Go binary")
		}
	}
}

func TestPclntabAllFuncs(t *testing.T) {
	stripped, _ := pclntabSkipIfNoBins(t)
	f := openSafe(t, stripped)
	tbl, err := f.Pclntab()
	if err != nil {
		t.Fatalf("Pclntab: %v", err)
	}
	funcs := tbl.AllFuncs()

	if len(funcs) < 10 {
		t.Fatalf("expected at least 10 functions, got %d", len(funcs))
	}
	t.Logf("resolved %d functions from stripped binary", len(funcs))

	for i, fn := range funcs {
		if fn.Offset == 0 {
			t.Errorf("function %s has zero offset", fn.Name)
		}
		if i > 0 && fn.Offset < funcs[i-1].Offset {
			t.Fatalf("functions not sorted at index %d", i)
		}
	}
}

func TestPclntabOffsetByNameDedup(t *testing.T) {
	stripped, unstripped := pclntabSkipIfNoBins(t)

	f := openSafe(t, stripped)
	tbl, err := f.Pclntab()
	if err != nil {
		t.Fatalf("Pclntab: %v", err)
	}

	// runtime.newproc has both ABIInternal and ABI0 entries in pclntab;
	// AllFuncs returns both, OffsetByName should return the larger one
	var allNewproc []UprobeOffset
	for _, fn := range tbl.AllFuncs() {
		if fn.Name == "runtime.newproc" {
			allNewproc = append(allNewproc, fn)
		}
	}

	off, ok := tbl.OffsetByName("runtime.newproc")
	if !ok {
		t.Fatal("OffsetByName: runtime.newproc not found")
	}

	t.Logf("AllFuncs returned %d entries for runtime.newproc", len(allNewproc))
	if len(allNewproc) < 2 {
		t.Skip("runtime.newproc has only one pclntab entry in this binary")
	}

	// deduplicated entry should match ELF symtab (ground truth)
	ef, err := elf.Open(unstripped)
	if err != nil {
		t.Fatalf("open unstripped: %v", err)
	}
	defer ef.Close()
	elfSyms, _ := ef.Symbols()
	for _, s := range elfSyms {
		if s.Name == "runtime.newproc" && elf.ST_TYPE(s.Info) == elf.STT_FUNC {
			sect := ef.Sections[s.Section]
			elfOff := s.Value - sect.Addr + sect.Offset
			if off == elfOff {
				t.Logf("OffsetByName picked offset 0x%x, matches ELF symtab", elfOff)
			} else {
				t.Errorf("OffsetByName picked 0x%x, ELF symtab has 0x%x", off, elfOff)
			}
			break
		}
	}
}

func TestPclntabRejectPreGo126(t *testing.T) {
	preGo126 := testutils.RepoRootPath("contrib/tester-progs/pclntab-go122-stripped")
	if _, err := os.Stat(preGo126); err != nil {
		t.Skipf("pclntab-go122-stripped not found: %v", err)
	}
	f := openSafe(t, preGo126)
	_, err := f.Pclntab()
	if err == nil {
		t.Fatal("expected error for pre-Go 1.26 binary")
	}
	t.Logf("correctly rejected: %v", err)
}

func TestPclntabOpenNotGo(t *testing.T) {
	f, err := OpenSafeELFFile("/bin/sh")
	if err != nil {
		t.Skipf("/bin/sh not available: %v", err)
	}
	defer f.Close()
	_, err = f.Pclntab()
	if err == nil {
		t.Fatal("expected error parsing non-Go binary")
	}
}

func TestPclntabOffsetsMatchELFSymtab(t *testing.T) {
	stripped, unstripped := pclntabSkipIfNoBins(t)

	// build ground truth from the unstripped binary's ELF symtab
	ef, err := elf.Open(unstripped)
	if err != nil {
		t.Fatalf("open unstripped binary: %v", err)
	}
	defer ef.Close()

	elfSyms, err := ef.Symbols()
	if err != nil {
		t.Fatalf("read ELF symbols: %v", err)
	}

	// symbol name -> file offset via ELF section headers
	elfOffsets := make(map[string]uint64)
	for _, s := range elfSyms {
		if elf.ST_TYPE(s.Info) != elf.STT_FUNC || s.Value == 0 {
			continue
		}
		if int(s.Section) < 0 || int(s.Section) >= len(ef.Sections) {
			continue
		}
		sect := ef.Sections[s.Section]
		elfOffsets[s.Name] = s.Value - sect.Addr + sect.Offset
	}

	f := openSafe(t, stripped)
	tbl, err := f.Pclntab()
	if err != nil {
		t.Fatalf("Pclntab: %v", err)
	}

	pclntabByName := make(map[string][]uint64)
	for _, fn := range tbl.AllFuncs() {
		pclntabByName[fn.Name] = append(pclntabByName[fn.Name], fn.Offset)
	}

	checkSymbols := []string{
		"runtime.main",
		"main.main",
		"runtime.schedinit",
		"runtime.mallocgc",
	}

	matched := 0
	for _, name := range checkSymbols {
		elfOff, inElf := elfOffsets[name]
		if !inElf {
			t.Logf("skipping %s: not in ELF symtab", name)
			continue
		}
		offsets, inPclntab := pclntabByName[name]
		if !inPclntab {
			t.Errorf("%s: in ELF symtab but missing from pclntab", name)
			continue
		}
		if !slices.Contains(offsets, elfOff) {
			t.Errorf("%s: ELF offset 0x%x not among pclntab offsets %v",
				name, elfOff, offsets)
			continue
		}
		// Verify OffsetByName returns the deduplicated offset that matches ELF symtab
		offByName, ok := tbl.OffsetByName(name)
		if !ok {
			t.Errorf("%s: OffsetByName not found", name)
			continue
		}
		if offByName != elfOff {
			t.Errorf("%s: OffsetByName returned 0x%x, ELF symtab has 0x%x",
				name, offByName, elfOff)
			continue
		}
		t.Logf("%s: offset 0x%x matches (OffsetByName verified)", name, elfOff)
		matched++
	}
	if matched == 0 {
		t.Fatal("no symbols were cross-validated")
	}
	t.Logf("cross-validated %d/%d symbols", matched, len(checkSymbols))
}
