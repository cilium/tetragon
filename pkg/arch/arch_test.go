package arch

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_addSyscallPrefix(t *testing.T) {
	symbol := "sys_test"
	arch := "test64"
	supportedArchPrefix[arch] = "__test64_"
	prefixedSymbol := supportedArchPrefix[arch] + symbol

	// adding prefix
	res, err := addSyscallPrefix(symbol, arch)
	assert.NoError(t, err)
	assert.Equal(t, prefixedSymbol, res)

	// doing nothing
	res, err = addSyscallPrefix(prefixedSymbol, arch)
	assert.NoError(t, err)
	assert.Equal(t, prefixedSymbol, res)

	// wrong prefix for current arch
	res, err = addSyscallPrefix("__x64_"+symbol, arch)
	assert.Error(t, err)
	assert.Empty(t, res)

	// not supported arch
	res, err = addSyscallPrefix(symbol, "unsupported64")
	assert.Error(t, err)
	assert.Empty(t, res)
}
