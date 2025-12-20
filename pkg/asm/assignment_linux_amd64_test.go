// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package asm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func FuzzAssignment(f *testing.F) {
	f.Add("rax=1")
	f.Add("rbp=128%rax")
	f.Add("rbp=0x20(%rsp)")
	f.Add("rsp=-1372(%rbp)")
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
	ass, err = ParseAssignment("rax=1")
	require.NoError(t, err)
	assert.Equal(t, ASM_ASSIGNMENT_TYPE_CONST, ass.Type)
	assert.Equal(t, uint64(1), ass.Off)
	assert.Equal(t, uint16(0x50), ass.Dst)
	assert.Equal(t, uint16(0x0), ass.Src)

	ass, err = ParseAssignment("rbx=-1")
	require.NoError(t, err)
	assert.Equal(t, ASM_ASSIGNMENT_TYPE_CONST, ass.Type)
	assert.Equal(t, uint64(0xffffffffffffffff), ass.Off)
	assert.Equal(t, uint16(0x28), ass.Dst)
	assert.Equal(t, uint16(0), ass.Src)

	ass, err = ParseAssignment("rcx=0x123")
	require.NoError(t, err)
	assert.Equal(t, ASM_ASSIGNMENT_TYPE_CONST, ass.Type)
	assert.Equal(t, uint64(0x123), ass.Off)
	assert.Equal(t, uint16(0x58), ass.Dst)
	assert.Equal(t, uint16(0), ass.Src)

	ass, err = ParseAssignment("rax=0xffffffffffffffff")
	require.NoError(t, err)
	assert.Equal(t, ASM_ASSIGNMENT_TYPE_CONST, ass.Type)
	assert.Equal(t, uint64(0xffffffffffffffff), ass.Off)
	assert.Equal(t, uint16(0x50), ass.Dst)
	assert.Equal(t, uint16(0), ass.Src)

	ass, err = ParseAssignment("rax=0x8000000000000002")
	require.NoError(t, err)
	assert.Equal(t, ASM_ASSIGNMENT_TYPE_CONST, ass.Type)
	assert.Equal(t, uint64(0x8000000000000002), ass.Off)
	assert.Equal(t, uint16(0x50), ass.Dst)
	assert.Equal(t, uint16(0), ass.Src)

	ass, err = ParseAssignment("rax=18446744073709551615")
	require.NoError(t, err)
	assert.Equal(t, ASM_ASSIGNMENT_TYPE_CONST, ass.Type)
	assert.Equal(t, uint64(0xffffffffffffffff), ass.Off)
	assert.Equal(t, uint16(0x50), ass.Dst)
	assert.Equal(t, uint16(0), ass.Src)

	// register
	ass, err = ParseAssignment("rsp=%rax")
	require.NoError(t, err)
	assert.Equal(t, ASM_ASSIGNMENT_TYPE_REG, ass.Type)
	assert.Equal(t, uint16(0x98), ass.Dst)
	assert.Equal(t, uint16(0x50), ass.Src)
	assert.Equal(t, uint64(0), ass.Off)

	// register + offset
	ass, err = ParseAssignment("rbp=128%rax")
	require.NoError(t, err)
	assert.Equal(t, ASM_ASSIGNMENT_TYPE_REG_OFF, ass.Type)
	assert.Equal(t, uint16(0x20), ass.Dst)
	assert.Equal(t, uint16(0x50), ass.Src)
	assert.Equal(t, uint64(128), ass.Off)

	ass, err = ParseAssignment("rax=0x80%rax")
	require.NoError(t, err)
	assert.Equal(t, ASM_ASSIGNMENT_TYPE_REG_OFF, ass.Type)
	assert.Equal(t, uint16(0x50), ass.Dst)
	assert.Equal(t, uint16(0x50), ass.Src)
	assert.Equal(t, uint64(0x80), ass.Off)

	// register deref
	ass, err = ParseAssignment("rsp=-1372(%rbp)")
	require.NoError(t, err)
	assert.Equal(t, ASM_ASSIGNMENT_TYPE_REG_DEREF, ass.Type)
	assert.Equal(t, uint16(0x98), ass.Dst)
	assert.Equal(t, uint16(0x20), ass.Src)
	assert.Equal(t, uint64(0xfffffffffffffaa4), ass.Off)

	ass, err = ParseAssignment("rbp=0x20(%rsp)")
	require.NoError(t, err)
	assert.Equal(t, ASM_ASSIGNMENT_TYPE_REG_DEREF, ass.Type)
	assert.Equal(t, uint16(0x20), ass.Dst)
	assert.Equal(t, uint16(0x98), ass.Src)
	assert.Equal(t, uint64(0x20), ass.Off)
}
