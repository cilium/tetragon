// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package ksyms

import (
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
