// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows && !nok8s

package generate

import (
	"os"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/testutils"
)

func TestUprobeSymbolsStrippedCgo(t *testing.T) {
	bin := testutils.RepoRootPath("contrib/tester-progs/pclntab-cgo-stripped")
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("%s not found: %v", bin, err)
	}
	symbols, err := uprobeSymbols(bin)
	require.NoError(t, err)
	// Go functions from .gopclntab next to the C functions in .dynsym
	for _, name := range []string{"main.main", "main.double", "add"} {
		require.Contains(t, symbols, name)
	}
	require.True(t, slices.IsSorted(symbols))
	require.Len(t, slices.Compact(slices.Clone(symbols)), len(symbols), "duplicate symbols")
}
