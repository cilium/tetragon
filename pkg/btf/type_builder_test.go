// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package btf

import (
	"bytes"
	"testing"

	"github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/require"
)

func TestParseBTFTypeSyntaxErrors(t *testing.T) {
	tests := []struct {
		name        string
		expr        string
		errContains string
	}{
		{
			name:        "Empty type string",
			expr:        "",
			errContains: "empty type expression",
		},
		{
			name:        "Pure whitespace string",
			expr:        "   ",
			errContains: "empty type expression",
		},
		{
			name:        "Pointer with no following type",
			expr:        "*",
			errContains: "expected type name",
		},
		{
			name:        "Unexpected token after valid type",
			expr:        "int)x",
			errContains: "unexpected token",
		},
		{
			name:        "Trailing garbage after valid type",
			expr:        "char* garbage",
			errContains: "unexpected token \"garbage\"",
		},
		{
			name:        "Empty array declaration",
			expr:        "int[]",
			errContains: "missing array size",
		},
		{
			name:        "Non-numeric array size",
			expr:        "int[sixteen]",
			errContains: "invalid array size",
		},
		{
			name:        "Negative array size",
			expr:        "int[-1]",
			errContains: "invalid array size",
		},
		{
			name:        "Unclosed array bracket",
			expr:        "int[64",
			errContains: "missing closing array bracket",
		},
		{
			name:        "Struct not in spec",
			expr:        "struct no_such",
			errContains: "failed to resolve struct",
		},
		{
			name:        "Union not in spec",
			expr:        "union no_such",
			errContains: "failed to resolve union",
		},
		{
			name:        "Enum not in spec",
			expr:        "enum no_such",
			errContains: "failed to resolve enum",
		},
		{
			name:        "Typedef not in spec",
			expr:        "no_such_t",
			errContains: "failed to resolve typedef",
		},
	}

	dummySpec := specFromBTFTypes(t, []btf.Type{btfChar()})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseBTFType(dummySpec, tt.expr)
			require.Error(t, err)
			require.ErrorContains(t, err, tt.errContains)
		})
	}
	t.Run("no BTF spec provided", func(t *testing.T) {
		_, err := ParseBTFType(nil, "int")
		require.Error(t, err)
		require.ErrorContains(t, err, "no BTF spec provided")
	})
}

func TestParseBTFTypePointerArrayCombinations(t *testing.T) {
	tests := []struct {
		name     string
		expr     string
		wantType btf.Type
	}{
		{
			name:     "Suffix pointer",
			expr:     "char*",
			wantType: wantPtr(wantChar()),
		},
		{
			name:     "Suffix pointer to char array",
			expr:     "char[64]*",
			wantType: wantPtr(wantArray(wantChar(), 64)),
		},
		{
			name:     "Double prefix pointer to char array",
			expr:     "char**[64]",
			wantType: wantArray(wantPtr(wantPtr(wantChar())), 64),
		},
		{
			name:     "Double suffix pointer to char array",
			expr:     "char[64]**",
			wantType: wantPtr(wantPtr(wantArray(wantChar(), 64))),
		},
		{
			name:     "Array of char pointers",
			expr:     "char*[64]",
			wantType: wantArray(wantPtr(wantChar()), 64),
		},
	}

	dummySpec := specFromBTFTypes(t, []btf.Type{btfChar()})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ty, err := ParseBTFType(dummySpec, tt.expr)
			require.NoError(t, err)
			require.Equal(t, tt.wantType, ty)
		})
	}
}

func TestParseBTFTypeSpecLookup(t *testing.T) {
	u32 := &btf.Int{Name: "unsigned int", Size: 4, Encoding: btf.Unsigned}
	primarySpec := specFromBTFTypes(t, []btf.Type{
		&btf.Struct{Name: "task_struct", Size: 8},
		&btf.Union{Name: "my_union", Size: 4},
		&btf.Enum{Name: "my_enum", Size: 4},
		u32,
		&btf.Typedef{Name: "pid_t", Type: u32},
	})

	taskStruct, _ := primarySpec.AnyTypeByName("task_struct")
	myUnion, _ := primarySpec.AnyTypeByName("my_union")
	myEnum, _ := primarySpec.AnyTypeByName("my_enum")
	pidT, _ := primarySpec.AnyTypeByName("pid_t")

	tests := []struct {
		name     string
		expr     string
		wantType btf.Type
	}{
		{
			name:     "Resolve explicit struct prefix",
			expr:     "struct task_struct *",
			wantType: wantPtr(taskStruct),
		},
		{
			name:     "Resolve explicit struct prefix",
			expr:     "struct task_struct *[123]",
			wantType: wantArray(wantPtr(taskStruct), 123),
		},
		{
			name:     "Resolve explicit union prefix",
			expr:     "union my_union *",
			wantType: wantPtr(myUnion),
		},
		{
			name:     "Resolve explicit enum prefix",
			expr:     "enum my_enum *",
			wantType: wantPtr(myEnum),
		},
		{
			name:     "Resolve typedef",
			expr:     "pid_t",
			wantType: pidT,
		},
		{
			name:     "Pointer to typedef",
			expr:     "pid_t*",
			wantType: wantPtr(pidT),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ty, err := ParseBTFType(primarySpec, tt.expr)
			require.NoError(t, err)
			require.Equal(t, tt.wantType, ty)
		})
	}
}

func specFromBTFTypes(t *testing.T, types []btf.Type) *btf.Spec {
	t.Helper()

	builder, err := btf.NewBuilder(types, nil)
	require.NoError(t, err)

	rawSpec, err := builder.Marshal(nil, nil)
	require.NoError(t, err)

	spec, err := btf.LoadSpecFromReader(bytes.NewReader(rawSpec))
	require.NoError(t, err)
	return spec
}

func wantPtr(target btf.Type) btf.Type {
	return &btf.Pointer{Target: target}
}

func wantArray(ty btf.Type, nelems uint32) btf.Type {
	return &btf.Array{
		Type:   ty,
		Index:  wantUnsignedInt(),
		Nelems: nelems,
	}
}

func wantChar() btf.Type {
	return &btf.Int{
		Name:     "char",
		Size:     1,
		Encoding: btf.Char,
	}
}

func wantUnsignedInt() btf.Type {
	return &btf.Int{
		Name:     "unsigned int",
		Size:     4,
		Encoding: btf.Unsigned,
	}
}
