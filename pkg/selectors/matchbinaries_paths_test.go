// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package selectors

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

func TestParseMatchBinaryDedupesPaths(t *testing.T) {
	k := NewKernelSelectorState(nil, nil, false, 0, nil, nil)
	b := &v1alpha1.BinarySelector{
		Operator: "In",
		Values:   []string{"/usr/bin/cat", "/usr/bin/cat", "/usr/bin/echo", "/usr/bin/cat"},
	}
	require.NoError(t, ParseMatchBinary(k, b, 0, matchBinaries))

	paths := k.MatchBinariesPaths()[0]
	require.Len(t, paths, 2)
	require.Equal(t, "/usr/bin/cat", strings.TrimRight(string(paths[0][:]), "\x00"))
	require.Equal(t, "/usr/bin/echo", strings.TrimRight(string(paths[1][:]), "\x00"))
}
