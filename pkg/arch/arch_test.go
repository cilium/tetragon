// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package arch

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_addSyscallPrefix(t *testing.T) {
	symbol := "sys_test"
	arch := "test64"
	supportedArchPrefix[arch] = "__test64_"
	prefixedSymbol := supportedArchPrefix[arch] + symbol

	// adding prefix
	res, err := addSyscallPrefix(symbol, arch)
	require.NoError(t, err)
	assert.Equal(t, prefixedSymbol, res)

	// doing nothing
	res, err = addSyscallPrefix(prefixedSymbol, arch)
	require.NoError(t, err)
	assert.Equal(t, prefixedSymbol, res)

	// wrong prefix for current arch
	res, err = addSyscallPrefix("__x64_"+symbol, arch)
	require.Error(t, err)
	assert.Empty(t, res)

	// not supported arch
	res, err = addSyscallPrefix(symbol, "unsupported64")
	require.Error(t, err)
	assert.Empty(t, res)
}
