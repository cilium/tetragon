// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build amd64 && linux
// +build amd64,linux

package elf

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseArgs(t *testing.T) {
	spec := UsdtSpec{
		ArgsStr: "-4@-1372(%rbp) -8@(%rbp) 8@%rax -4@$-9",
	}

	err := parseArgs(&spec)

	require.NoError(t, err)
	assert.Equal(t, uint32(4), spec.ArgsCnt)

	var arg *UsdtArg

	/* -4@-1372(%rbp) */
	arg = &spec.Args[0]
	assert.Equal(t, USDT_ARG_TYPE_REG_DEREF, arg.Type)
	assert.Equal(t, uint16(32), arg.RegOff)
	assert.Equal(t, uint64(0xfffffffffffffaa4) /* -1372 */, arg.ValOff)
	assert.True(t, arg.Signed)
	assert.Equal(t, uint8(32), arg.Shift)

	/* -8@(%rbp) */
	arg = &spec.Args[1]
	assert.Equal(t, USDT_ARG_TYPE_REG_DEREF, arg.Type)
	assert.Equal(t, uint16(32), arg.RegOff)
	assert.Equal(t, uint64(0), arg.ValOff)
	assert.True(t, arg.Signed)
	assert.Equal(t, uint8(0), arg.Shift)

	/* 8@%rax */
	arg = &spec.Args[2]
	assert.Equal(t, USDT_ARG_TYPE_REG, arg.Type)
	assert.Equal(t, uint16(80), arg.RegOff)
	assert.Equal(t, uint64(0), arg.ValOff)
	assert.False(t, arg.Signed)
	assert.Equal(t, uint8(0), arg.Shift)

	/* -4@$-9 */
	arg = &spec.Args[3]
	assert.Equal(t, USDT_ARG_TYPE_CONST, arg.Type)
	assert.Equal(t, uint16(0), arg.RegOff)
	assert.Equal(t, uint64(0xfffffffffffffff7) /* -9 */, arg.ValOff)
	assert.True(t, arg.Signed)
	assert.Equal(t, uint8(32), arg.Shift)
}
