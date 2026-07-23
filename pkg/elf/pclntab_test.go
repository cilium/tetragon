// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux

package elf

import (
	"debug/elf"
	"encoding/binary"
	"os"
	"slices"
	"testing"

	"github.com/cilium/tetragon/pkg/testutils"
)

// A container-controlled ELF can inflate the pclntab function count so that
// debug/gosym's make([]Func, nfunctab) fatally OOMs the agent. The guard must
// reject a count that cannot fit in the section before gosym ever sees it.
func TestPclntabRejectOversizedFunctab(t *testing.T) {
	makeHdr := func(ptrSize byte, nfunctab uint64, total int) []byte {
		b := make([]byte, total)
		b[7] = ptrSize
		binary.LittleEndian.PutUint64(b[8:], nfunctab)
		return b
	}
	if err := pclntabRejectOversizedFunctab(makeHdr(8, 0xFFFFFFFF, 64), binary.LittleEndian); err == nil {
		t.Fatal("expected oversized functab count to be rejected")
	}
	if err := pclntabRejectOversizedFunctab(makeHdr(8, 3, 4096), binary.LittleEndian); err != nil {
		t.Fatalf("expected in-bounds functab count to be accepted: %v", err)
	}
	if err := pclntabRejectOversizedFunctab([]byte{0, 0, 0, 0, 0, 0, 0, 8}, binary.LittleEndian); err == nil {
		t.Fatal("expected truncated header to be rejected")
	}
}

// A container can craft a big-endian pclntab so a little-endian-only guard reads
// a small count while gosym (which infers endianness from the magic) reads a
// huge one and fatally OOMs. The guard must read nfunctab in the magic's byte
// order.
func TestPclntabRejectOversizedFunctabBigEndian(t *testing.T) {
	hdr := make([]byte, 64)
	binary.BigEndian.PutUint32(hdr[0:], 0xfffffff1) // Go 1.20+ magic, big-endian
	hdr[7] = 8                                      // ptrSize
	// nfunctab occupies hdr[8:16]; gosym truncates uintptr to uint32 (low 32
	// bits). Big-endian low 32 bits come from hdr[12:16]: 0xFF000000 ~= 4.2e9,
	// which cannot fit a 64-byte section. Little-endian would read hdr[8:12] = 0.
	hdr[12] = 0xFF

	bo, err := pclntabByteOrder(hdr)
	if err != nil {
		t.Fatalf("byte order detection failed: %v", err)
	}
	if bo != binary.BigEndian {
		t.Fatalf("expected big-endian detection, got %v", bo)
	}
	if err := pclntabRejectOversizedFunctab(hdr, bo); err == nil {
		t.Fatal("big-endian oversized functab must be rejected (LE-only guard would pass it)")
	}
	// Sanity: a LE-only read of the same header sees a small count and passes,
	// which is exactly the bypass being closed.
	if err := pclntabRejectOversizedFunctab(hdr, binary.LittleEndian); err != nil {
		t.Fatalf("LE read of this header is small and should pass: %v", err)
	}
}

func TestPclntabByteOrderRejectsUnknownMagic(t *testing.T) {
	if _, err := pclntabByteOrder([]byte{0, 0, 0, 0, 0, 0, 0, 8}); err == nil {
		t.Fatal("expected unrecognized magic to be rejected")
	}
}

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
