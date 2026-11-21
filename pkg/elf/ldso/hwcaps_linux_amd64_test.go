// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package ldso

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestX86HwcapsSubdirs(t *testing.T) {
	tests := []struct {
		name     string
		features x86Feature
		want     []string
	}{
		{name: "baseline", want: nil},
		{name: "v2", features: x86V2, want: []string{"x86-64-v2"}},
		{name: "v3", features: x86V3, want: []string{"x86-64-v3", "x86-64-v2"}},
		{name: "v4", features: x86V4, want: []string{"x86-64-v4", "x86-64-v3", "x86-64-v2"}},
		{name: "v3 without MOVBE", features: x86V3 &^ x86MOVBE, want: []string{"x86-64-v2"}},
		{name: "v3 without OS AVX support", features: x86V3 &^ x86OSXSAVE, want: []string{"x86-64-v2"}},
		{name: "v4 without AVX512VL", features: x86V4 &^ x86AVX512VL, want: []string{"x86-64-v3", "x86-64-v2"}},
		{name: "levels are cumulative", features: x86V4 &^ x86LAHF, want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, x86HwcapsSubdirs(tt.features))
		})
	}
}

// TestX86HostFeatures checks every feature is mapped to a host CPU flag,
// exactly once.
func TestX86HostFeatures(t *testing.T) {
	var all x86Feature
	for _, f := range x86HostFeatures {
		require.NotZero(t, f.feature)
		require.Zero(t, f.feature&(f.feature-1), "%#x is not a single feature", f.feature)
		require.Zero(t, all&f.feature, "%#x mapped twice", f.feature)
		all |= f.feature
	}
	// x86AVX512VL is the last feature
	require.Equal(t, x86AVX512VL<<1-1, all)
	require.Equal(t, x86V4, all)
}
