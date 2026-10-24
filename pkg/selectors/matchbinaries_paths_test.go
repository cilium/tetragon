// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package selectors

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWriteMatchBinariesPathDedupes(t *testing.T) {
	k := NewKernelSelectorState(nil, nil, false, 0, nil, nil)
	k.WriteMatchBinariesPath(0, "/usr/bin/cat")
	k.WriteMatchBinariesPath(0, "/usr/bin/cat")
	k.WriteMatchBinariesPath(0, "/usr/bin/echo")

	paths := k.MatchBinariesPaths()[0]
	require.Len(t, paths, 2)
}
