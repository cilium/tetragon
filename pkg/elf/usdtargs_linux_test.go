// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package elf

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseArgsEmpty(t *testing.T) {
	spec := UsdtSpec{}

	require.NoError(t, parseArgs(&spec))
	require.Zero(t, spec.ArgsCnt)
}
