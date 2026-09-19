// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package asm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func FuzzAssignment(f *testing.F) {
	f.Add("x0=1")
	f.Add("x29=128%x0")
	f.Add("x29=0x20(%sp)")
	f.Add("sp=-1372(%x29)")
	f.Fuzz(func(t *testing.T, exp string) {
		ass, err := ParseAssignment(exp)
		if err != nil && ass != nil {
			t.Errorf("ass:%v, err:%v", ass, err)
		}
	})
}

func TestAssignment(t *testing.T) {
	var (
		ass *Assignment
		err error
	)

	// constants — octal form
	ass, err = ParseAssignment("x0=010")
	require.NoError(t, err)
	assert.Equal(t, ASM_ASSIGNMENT_TYPE_CONST, ass.Type)
	assert.Equal(t, uint64(8), ass.Off)
	assert.Equal(t, uint16(0x0), ass.Dst)
	assert.Equal(t, uint16(0x0), ass.Src)

	// constants
	ass, err = ParseAssignment("x0=1")
	require.NoError(t, err)
	assert.Equal(t, ASM_ASSIGNMENT_TYPE_CONST, ass.Type)
	assert.Equal(t, uint64(1), ass.Off)
	assert.Equal(t, uint16(0x0), ass.Dst)
	assert.Equal(t, uint16(0x0), ass.Src)

	ass, err = ParseAssignment("x19=-1")
	require.NoError(t, err)
	assert.Equal(t, ASM_ASSIGNMENT_TYPE_CONST, ass.Type)
	assert.Equal(t, uint64(0xffffffffffffffff), ass.Off)
	assert.Equal(t, uint16(0x98), ass.Dst)
	assert.Equal(t, uint16(0), ass.Src)

	ass, err = ParseAssignment("x20=0x123")
	require.NoError(t, err)
	assert.Equal(t, ASM_ASSIGNMENT_TYPE_CONST, ass.Type)
	assert.Equal(t, uint64(0x123), ass.Off)
	assert.Equal(t, uint16(0xa0), ass.Dst)
	assert.Equal(t, uint16(0), ass.Src)

	// register
	ass, err = ParseAssignment("sp=%x0")
	require.NoError(t, err)
	assert.Equal(t, ASM_ASSIGNMENT_TYPE_REG, ass.Type)
	assert.Equal(t, uint16(0xf8), ass.Dst)
	assert.Equal(t, uint16(0x0), ass.Src)
	assert.Equal(t, uint64(0), ass.Off)

	ass, err = ParseAssignment("sp = %x0")
	require.NoError(t, err)
	assert.Equal(t, ASM_ASSIGNMENT_TYPE_REG, ass.Type)
	assert.Equal(t, uint16(0xf8), ass.Dst)
	assert.Equal(t, uint16(0x0), ass.Src)
	assert.Equal(t, uint64(0), ass.Off)

	// register + offset
	ass, err = ParseAssignment("x29=128%x0")
	require.NoError(t, err)
	assert.Equal(t, ASM_ASSIGNMENT_TYPE_REG_OFF, ass.Type)
	assert.Equal(t, uint16(0xe8), ass.Dst)
	assert.Equal(t, uint16(0x0), ass.Src)
	assert.Equal(t, uint64(128), ass.Off)

	ass, err = ParseAssignment("x29 = 010 %x0")
	require.NoError(t, err)
	assert.Equal(t, ASM_ASSIGNMENT_TYPE_REG_OFF, ass.Type)
	assert.Equal(t, uint16(0xe8), ass.Dst)
	assert.Equal(t, uint16(0x0), ass.Src)
	assert.Equal(t, uint64(8), ass.Off)

	ass, err = ParseAssignment("x1=0x80%x1")
	require.NoError(t, err)
	assert.Equal(t, ASM_ASSIGNMENT_TYPE_REG_OFF, ass.Type)
	assert.Equal(t, uint16(0x8), ass.Dst)
	assert.Equal(t, uint16(0x8), ass.Src)
	assert.Equal(t, uint64(0x80), ass.Off)

	// register deref — no-offset form
	ass, err = ParseAssignment("x29=(%sp)")
	require.NoError(t, err)
	assert.Equal(t, ASM_ASSIGNMENT_TYPE_REG_DEREF, ass.Type)
	assert.Equal(t, uint16(0xe8), ass.Dst)
	assert.Equal(t, uint16(0xf8), ass.Src)
	assert.Equal(t, uint64(0), ass.Off)

	// register deref
	ass, err = ParseAssignment("sp=-1372(%x29)")
	require.NoError(t, err)
	assert.Equal(t, ASM_ASSIGNMENT_TYPE_REG_DEREF, ass.Type)
	assert.Equal(t, uint16(0xf8), ass.Dst)
	assert.Equal(t, uint16(0xe8), ass.Src)
	assert.Equal(t, uint64(0xfffffffffffffaa4), ass.Off)

	ass, err = ParseAssignment("x29=0x20(%sp)")
	require.NoError(t, err)
	assert.Equal(t, ASM_ASSIGNMENT_TYPE_REG_DEREF, ass.Type)
	assert.Equal(t, uint16(0xe8), ass.Dst)
	assert.Equal(t, uint16(0xf8), ass.Src)
	assert.Equal(t, uint64(0x20), ass.Off)

	ass, err = ParseAssignment("x29 = 0x20 ( %sp )")
	require.NoError(t, err)
	assert.Equal(t, ASM_ASSIGNMENT_TYPE_REG_DEREF, ass.Type)
	assert.Equal(t, uint16(0xe8), ass.Dst)
	assert.Equal(t, uint16(0xf8), ass.Src)
	assert.Equal(t, uint64(0x20), ass.Off)

	ass, err = ParseAssignment("sp=010(%x29)")
	require.NoError(t, err)
	assert.Equal(t, ASM_ASSIGNMENT_TYPE_REG_DEREF, ass.Type)
	assert.Equal(t, uint16(0xf8), ass.Dst)
	assert.Equal(t, uint16(0xe8), ass.Src)
	assert.Equal(t, uint64(8), ass.Off)
}

func TestAssignmentInvalid(t *testing.T) {
	tests := []string{
		"x0=",
		"=1",
		"x0=1=2",
		"x 0=1",
		"x0=1 2",
		"x0=abc",
		"x29=0x2 0(%sp)",
		"x29=0x20(%sp",
		"x29=0x20(%sp)junk",
		"x29=0x20(% sp)",
		"sp=%x0)",
		"sp=% x0",
		"sp=%x 0",
		"sp=%x0junk",
		"sp=8% x0",
		"sp=8%x0 garbage",
		"sp=8%x 0",
		"x0=0x20()",
		"x0=0x20(%notareg)",
	}

	for _, exp := range tests {
		t.Run(exp, func(t *testing.T) {
			ass, err := ParseAssignment(exp)
			require.Error(t, err)
			assert.Nil(t, ass)
		})
	}
}

func TestCutCelAssignment(t *testing.T) {
	tests := []struct {
		in   string
		reg  string
		expr string
	}{
		{"x0=cel(41 + 1)", "x0", "41+1"},
		{"x0=cel(data0 - data1 + data2)", "x0", "data0-data1+data2"},
		{"x0=cel(and(data0, data1))", "x0", "and(data0,data1)"},
		{"x0=cel(data0 == 5)", "x0", "data0==5"},
		{"w0=cel(data0)", "w0", "data0"},
		{"x0 = cel(data0 + 1)", "x0", "data0+1"},
	}

	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			reg, expr, ok, err := CutCelAssignment(tc.in)
			t.Logf("in=%q -> reg=%q expr=%q ok=%v err=%v", tc.in, reg, expr, ok, err)
			require.True(t, ok)
			assert.Equal(t, tc.reg, reg)
			assert.Equal(t, tc.expr, expr)
			assert.Nil(t, err)
		})
	}
}

func TestCutCelAssignmentNotCel(t *testing.T) {
	tests := []string{
		"x0=11",
		"x29=(%sp)",
		"sp=16%sp",
	}

	for _, exp := range tests {
		t.Run(exp, func(t *testing.T) {
			reg, expr, ok, err := CutCelAssignment(exp)
			t.Logf("in=%q -> reg=%q expr=%q ok=%v err=%v", exp, reg, expr, ok, err)
			assert.False(t, ok)
			assert.Nil(t, err)
		})
	}
}
