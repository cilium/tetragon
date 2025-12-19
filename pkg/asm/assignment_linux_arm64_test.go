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

	// register + offset
	ass, err = ParseAssignment("x29=128%x0")
	require.NoError(t, err)
	assert.Equal(t, ASM_ASSIGNMENT_TYPE_REG_OFF, ass.Type)
	assert.Equal(t, uint16(0xe8), ass.Dst)
	assert.Equal(t, uint16(0x0), ass.Src)
	assert.Equal(t, uint64(128), ass.Off)

	ass, err = ParseAssignment("x1=0x80%x1")
	require.NoError(t, err)
	assert.Equal(t, ASM_ASSIGNMENT_TYPE_REG_OFF, ass.Type)
	assert.Equal(t, uint16(0x8), ass.Dst)
	assert.Equal(t, uint16(0x8), ass.Src)
	assert.Equal(t, uint64(0x80), ass.Off)

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
}
