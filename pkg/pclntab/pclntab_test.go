// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package pclntab

import (
	"debug/elf"
	"os"
	"slices"
	"testing"
)

const (
	strippedBin   = "testdata/node_exporter-stripped"
	unstrippedBin = "testdata/node_exporter-unstripped"
	preGo126Bin   = "testdata/node_exporter-go122-stripped"
)

func skipIfNoTestdata(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(strippedBin); err != nil {
		t.Skipf("testdata not found (run make -C testdata): %v", err)
	}
	if _, err := os.Stat(unstrippedBin); err != nil {
		t.Skipf("testdata not found (run make -C testdata): %v", err)
	}
}

func TestIsStrippedGoBinary(t *testing.T) {
	skipIfNoTestdata(t)

	if !IsStrippedGoBinary(strippedBin) {
		t.Fatal("expected stripped binary to be detected as stripped Go binary")
	}
	if IsStrippedGoBinary(unstrippedBin) {
		t.Fatal("expected unstripped binary to NOT be detected as stripped")
	}
	if IsStrippedGoBinary("/bin/sh") {
		t.Fatal("expected /bin/sh to NOT be detected as stripped Go binary")
	}
}

func TestAllFuncs(t *testing.T) {
	skipIfNoTestdata(t)
	funcs, err := AllFuncs(strippedBin)
	if err != nil {
		t.Fatalf("AllFuncs: %v", err)
	}

	if len(funcs) < 10000 {
		t.Fatalf("expected >10k functions from node_exporter, got %d", len(funcs))
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

func TestLookupDedup(t *testing.T) {
	skipIfNoTestdata(t)

	// runtime.newproc has both ABIInternal and ABI0 entries in pclntab
	// AllFuncs returns both; Lookup should return one (the larger)
	allFuncs, err := AllFuncs(strippedBin)
	if err != nil {
		t.Fatalf("AllFuncs: %v", err)
	}
	var allNewproc []FuncOffset
	for _, fn := range allFuncs {
		if fn.Name == "runtime.newproc" {
			allNewproc = append(allNewproc, fn)
		}
	}

	deduped, err := Lookup(strippedBin, []string{"runtime.newproc"})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}

	t.Logf("AllFuncs returned %d entries for runtime.newproc, Lookup returned %d", len(allNewproc), len(deduped))
	if len(allNewproc) < 2 {
		t.Skip("runtime.newproc has only one pclntab entry in this binary")
	}
	if len(deduped) != 1 {
		t.Fatalf("expected Lookup to deduplicate to 1 entry, got %d", len(deduped))
	}

	// deduplicated entry should match ELF symtab (ground truth)
	ef, err := elf.Open(unstrippedBin)
	if err != nil {
		t.Fatalf("open unstripped: %v", err)
	}
	defer ef.Close()
	elfSyms, _ := ef.Symbols()
	for _, s := range elfSyms {
		if s.Name == "runtime.newproc" && elf.ST_TYPE(s.Info) == elf.STT_FUNC {
			sect := ef.Sections[s.Section]
			elfOff := s.Value - sect.Addr + sect.Offset
			if deduped[0].Offset == elfOff {
				t.Logf("Lookup picked offset 0x%x, matches ELF symtab", elfOff)
			} else {
				t.Errorf("Lookup picked 0x%x, ELF symtab has 0x%x",
					deduped[0].Offset, elfOff)
			}
			break
		}
	}
}

func TestRejectPreGo126(t *testing.T) {
	if _, err := os.Stat(preGo126Bin); err != nil {
		t.Skipf("pre-Go 1.26 testdata not found (run make -C testdata): %v", err)
	}
	_, err := AllFuncs(preGo126Bin)
	if err == nil {
		t.Fatal("expected error for pre-Go 1.26 binary")
	}
	t.Logf("correctly rejected: %v", err)
}

func TestAllFuncsNotGo(t *testing.T) {
	_, err := AllFuncs("/bin/sh")
	if err == nil {
		t.Fatal("expected error parsing non-Go binary")
	}
}

func TestOffsetsMatchELFSymtab(t *testing.T) {
	skipIfNoTestdata(t)

	// build ground truth from the unstripped binary's ELF symtab
	ef, err := elf.Open(unstrippedBin)
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

	pclntabAllFuncs, err := AllFuncs(strippedBin)
	if err != nil {
		t.Fatalf("AllFuncs: %v", err)
	}

	pclntabByName := make(map[string][]uint64)
	for _, fn := range pclntabAllFuncs {
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
		} else {
			t.Logf("%s: offset 0x%x matches", name, elfOff)
			matched++
		}
	}
	if matched == 0 {
		t.Fatal("no symbols were cross-validated")
	}
	t.Logf("cross-validated %d/%d symbols", matched, len(checkSymbols))
}
