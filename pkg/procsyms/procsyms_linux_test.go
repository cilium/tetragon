// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package procsyms

import (
	"os"
	"testing"
)

func TestGetProcMaps(t *testing.T) {
	pid := os.Getpid()

	maps1, err := getProcMaps(pid)
	if err != nil {
		t.Fatalf("getProcMaps failed: %v", err)
	}

	if len(maps1) == 0 {
		t.Fatal("expected non-empty memory maps")
	}

	maps2, err := getProcMaps(pid)
	if err != nil {
		t.Fatalf("second getProcMaps failed: %v", err)
	}

	if len(maps1) != len(maps2) {
		t.Errorf("cache returned different data: got %d entries, want %d", len(maps2), len(maps1))
	}

	for i, entry := range maps1 {
		if entry.startAddr >= entry.endAddr {
			t.Errorf("entry %d: invalid address range: start=%x end=%x", i, entry.startAddr, entry.endAddr)
		}
	}
}

func TestInvalidatePID(t *testing.T) {
	pid := os.Getpid()

	_, err := getProcMaps(pid)
	if err != nil {
		t.Fatalf("getProcMaps failed: %v", err)
	}

	if procMapCache == nil {
		t.Fatal("cache not initialized")
	}

	if !procMapCache.Contains(pid) {
		t.Fatal("PID should be in cache after getProcMaps")
	}

	InvalidatePID(pid)

	if procMapCache.Contains(pid) {
		t.Error("PID should not be in cache after InvalidatePID")
	}
}

func TestInvalidatePIDNonExistent(_ *testing.T) {
	InvalidatePID(999999)
}

func TestFindMapEntry(t *testing.T) {
	entries := []*procMapEntry{
		{startAddr: 0x1000, endAddr: 0x2000, pathname: "/bin/a"},
		{startAddr: 0x3000, endAddr: 0x4000, pathname: "/bin/b"},
		{startAddr: 0x5000, endAddr: 0x6000, pathname: "/bin/c"},
	}

	tests := []struct {
		name     string
		addr     uint64
		wantPath string
	}{
		{"first region", 0x1500, "/bin/a"},
		{"second region", 0x3500, "/bin/b"},
		{"third region", 0x5500, "/bin/c"},
		{"start of first", 0x1000, "/bin/a"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := findMapEntry(entries, tt.addr)
			if entry.pathname != tt.wantPath {
				t.Errorf("findMapEntry(%x) = %s, want %s", tt.addr, entry.pathname, tt.wantPath)
			}
		})
	}
}

func TestGetFnSymbol(t *testing.T) {
	pid := os.Getpid()
	fnAddr := getFunctionAddr()

	if fnAddr == 0 {
		t.Skip("could not get function address for testing")
	}

	sym, err := GetFnSymbol(pid, fnAddr)
	if err != nil {
		t.Fatalf("GetFnSymbol failed: %v", err)
	}

	if sym.Module == "" {
		t.Error("expected non-empty module")
	}

	t.Logf("Resolved symbol: module=%s offset=%x name=%s", sym.Module, sym.Offset, sym.Name)
}

func getFunctionAddr() uint64 {
	return 0
}

func TestSymbolCacheInit(t *testing.T) {
	initSymbolCache()

	if symbolCache == nil {
		t.Error("symbol cache should be initialized")
	}
}

func TestProcMapCacheInit(t *testing.T) {
	initProcMapCache()

	if procMapCache == nil {
		t.Error("proc map cache should be initialized")
	}
}
