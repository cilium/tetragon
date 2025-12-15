// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package elf

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseArgs(t *testing.T) {
	spec := UsdtSpec{
		ArgsStr: "-1@x0 4@5 8@[x12] -4@[x30,-40] -4@[x31,-40] 8@[sp,120] -1@[x0,x1] -4@[sp, 12]",
	}

	err := parseArgs(&spec)

	require.NoError(t, err)
	assert.Equal(t, uint32(8), spec.ArgsCnt)

	var arg *UsdtArg

	/* -1@x0 */
	arg = &spec.Args[0]
	assert.Equal(t, USDT_ARG_TYPE_REG, arg.Type)
	assert.Equal(t, uint16(0), arg.RegOff)
	assert.Equal(t, uint64(0), arg.ValOff)
	assert.True(t, arg.Signed)
	assert.Equal(t, uint8(56), arg.Shift)

	/* 4@5 */
	arg = &spec.Args[1]
	assert.Equal(t, USDT_ARG_TYPE_CONST, arg.Type)
	assert.Equal(t, uint16(0), arg.RegOff)
	assert.Equal(t, uint64(5), arg.ValOff)
	assert.False(t, arg.Signed)
	assert.Equal(t, uint8(32), arg.Shift)

	/* 8@[x12] */
	arg = &spec.Args[2]
	assert.Equal(t, USDT_ARG_TYPE_REG_DEREF, arg.Type)
	assert.Equal(t, uint16(96), arg.RegOff)
	assert.Equal(t, uint64(0), arg.ValOff)
	assert.False(t, arg.Signed)
	assert.Equal(t, uint8(0), arg.Shift)

	/* -4@[x30,-40] */
	arg = &spec.Args[3]
	assert.Equal(t, USDT_ARG_TYPE_REG_DEREF, arg.Type)
	assert.Equal(t, uint16(240), arg.RegOff)
	assert.Equal(t, uint64(0xffffffffffffffd8) /* -40 */, arg.ValOff)
	assert.True(t, arg.Signed)
	assert.Equal(t, uint8(32), arg.Shift)

	/* -4@[x31,-40] */
	arg = &spec.Args[4]
	assert.Equal(t, USDT_ARG_TYPE_REG_DEREF, arg.Type)
	assert.Equal(t, uint16(248), arg.RegOff) // 31 -> sp
	assert.Equal(t, uint64(0xffffffffffffffd8) /* -40 */, arg.ValOff)
	assert.True(t, arg.Signed)
	assert.Equal(t, uint8(32), arg.Shift)

	/* 8@[sp,120] */
	arg = &spec.Args[5]
	assert.Equal(t, USDT_ARG_TYPE_REG_DEREF, arg.Type)
	assert.Equal(t, uint16(248), arg.RegOff)
	assert.Equal(t, uint64(120), arg.ValOff)
	assert.False(t, arg.Signed)
	assert.Equal(t, uint8(0), arg.Shift)

	/* -1@[x0,x1] */
	arg = &spec.Args[6]
	assert.Equal(t, USDT_ARG_TYPE_SIB, arg.Type)
	assert.Equal(t, uint16(0), arg.RegOff)
	assert.Equal(t, uint16(8), arg.RegIdxOff)
	assert.Equal(t, uint64(0), arg.ValOff)
	assert.True(t, arg.Signed)
	assert.Equal(t, uint8(56), arg.Shift)

	/* -4@[sp, 12] */
	arg = &spec.Args[7]
	assert.Equal(t, USDT_ARG_TYPE_REG_DEREF, arg.Type)
	assert.Equal(t, uint16(248), arg.RegOff)
	assert.Equal(t, uint64(12), arg.ValOff)
	assert.True(t, arg.Signed)
	assert.Equal(t, uint8(32), arg.Shift)
}
