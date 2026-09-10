// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/tetragoninfo"
)

func TestCheckCLIFlags(t *testing.T) {
	flags := []CLIFlag{
		{Name: "bool-flag", Value: true},
		{Name: "int-slice-flag", Value: []int{42, 43}},
	}

	require.Empty(t, CheckCLIFlags(nil, flags))
	require.Empty(t, CheckCLIFlags(&tetragoninfo.Info{Conf: map[string]any{
		"bool-flag": true, "int-slice-flag": []any{float64(42), float64(43)},
	}}, flags))
	require.Equal(t,
		"agent does not satisfy required CLI flags: --bool-flag=true --int-slice-flag=42,43",
		CheckCLIFlags(&tetragoninfo.Info{Conf: map[string]any{"bool-flag": false}}, flags),
	)
	require.Equal(t,
		"agent does not satisfy required CLI flags: --bool-flag=true --int-slice-flag=42,43",
		CheckCLIFlags(&tetragoninfo.Info{Conf: map[string]any{}}, flags),
	)
}

func TestCLIFlagValuesEqualFloatString(t *testing.T) {
	require.True(t, cliFlagValuesEqual("0.01", float64(0.01)))
	require.False(t, cliFlagValuesEqual("0", float64(0.01)))
	require.False(t, cliFlagValuesEqual("invalid", float64(0.01)))
}

func TestBuilderWithCLIFlags(t *testing.T) {
	builder := NewBuilder("cli-flags").WithCLIFlags(
		CLIFlag{Name: "enable-process-cred", Value: true},
		CLIFlag{Name: "enable-process-ns", Value: true},
	)

	require.Equal(t, []CLIFlag{
		{Name: "enable-process-cred", Value: true},
		{Name: "enable-process-ns", Value: true},
	}, builder.policytest.CLIFlags)
}
