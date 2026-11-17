// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package ksyms

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGetFnOffset(t *testing.T) {
	ksyms := &Ksyms{
		table: []ksym{
			{addr: 0x100, name: "addr1", ty: "t"},
			{addr: 0x200, name: "addr2", ty: "t"},
			{addr: 0x300, name: "addr3", ty: "w"},
			{addr: 0x400, name: "addr4", ty: "t"},
			{addr: 0x500, name: "addr5", ty: "t"},
			{addr: 0x600, name: "addr6", ty: "t"},
			{addr: 0x700, name: "addr7", ty: "t"},
			{addr: 0x800, name: "addr8", ty: "t"},
			{addr: 0x900, name: "addr9", ty: "t"},
			{addr: 0xa00, name: "addr10", ty: "t"},
		},
	}

	tests := []struct {
		name    string
		addr    uint64
		wantErr bool
		want    FnOffset
	}{
		{
			name: "valid first address",
			addr: 0x100,
			want: FnOffset{SymName: "addr1", Offset: 0},
		},
		{
			name: "addr 0x110",
			addr: 0x110,
			want: FnOffset{SymName: "addr1", Offset: 0x10},
		},
		{
			name: "addr 0x410",
			addr: 0x410,
			want: FnOffset{SymName: "addr4", Offset: 0x10},
		},
		{
			name: "addr 0x50f",
			addr: 0x50f,
			want: FnOffset{SymName: "addr5", Offset: 0xf},
		},
		{
			name: "addr 0x550",
			addr: 0x550,
			want: FnOffset{SymName: "addr5", Offset: 0x050},
		},
		{
			name: "addr 0x900",
			addr: 0x900,
			want: FnOffset{SymName: "addr8", Offset: 0x100},
		},
		{
			name:    "address is before first symbol",
			addr:    0x090,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ksyms.getFnOffset(tt.addr)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Unexpected error: %v", err)
			}
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error: %v", err)
				}
				return
			}
			if got.SymName != tt.want.SymName {
				t.Fatalf("Symbol name (%v) did not match expected value (%v) for %v", got.SymName, tt.want.SymName, tt.name)
			}
			if got.Offset != tt.want.Offset {
				t.Fatalf("Symbol offset (%x) did not match expected value (%x) for %v", got.Offset, tt.want.Offset, tt.name)
			}
		})
	}
}

func TestHasSymbol(t *testing.T) {
	const kallsyms = `ffffffff81000000 T _stext
ffffffff81001000 t do_one_initcall
ffffffff81234560 T acct_process
ffffffff81234570 T disassociate_ctty_x
ffffffffc0a01000 t mod_helper	[some_module]
ffffffffc0a02000 T acct_process_mod	[some_module]
`
	path := filepath.Join(t.TempDir(), "kallsyms")
	if err := os.WriteFile(path, []byte(kallsyms), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		symbol string
		want   bool
	}{
		{"present", "acct_process", true},
		{"present, first line", "_stext", true},
		{"present in a module", "mod_helper", true},
		{"absent", "disassociate_ctty", false},
		{"shorter name is not a match", "acct", false},
		{"longer name is not a match", "acct_process_mod2", false},
		{"address is not a symbol", "ffffffff81234560", false},
		{"type is not a symbol", "T", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := HasSymbol(path, tc.symbol)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("HasSymbol(%q) = %v, want %v", tc.symbol, got, tc.want)
			}
		})
	}
}

func TestHasSymbolIgnoresMalformedLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kallsyms")
	content := "garbage\n\nffffffff81000000 T\nffffffff81234560 T acct_process\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := HasSymbol(path, "acct_process")
	if err != nil {
		t.Fatal(err)
	}
	if !got {
		t.Fatal("HasSymbol(acct_process) = false, want true")
	}
}

func TestHasSymbolMissingFile(t *testing.T) {
	if _, err := HasSymbol(filepath.Join(t.TempDir(), "does-not-exist"), "acct_process"); err == nil {
		t.Fatal("HasSymbol on a missing file returned no error")
	}
}
