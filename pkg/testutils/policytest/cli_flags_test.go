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
		{Name: "enable-tcp", Value: true},
		{Name: "multicast-ports", Value: []int{8818, 8819}},
	}

	require.Empty(t, CheckCLIFlags(nil, flags))
	require.Empty(t, CheckCLIFlags(&tetragoninfo.Info{Conf: map[string]any{
		"enable-tcp": true, "multicast-ports": []any{float64(8818), float64(8819)},
	}}, flags))
	require.Equal(t,
		"agent does not satisfy required CLI flags: --enable-tcp=true --multicast-ports=8818,8819",
		CheckCLIFlags(&tetragoninfo.Info{Conf: map[string]any{"enable-tcp": false}}, flags),
	)
	require.Equal(t,
		"agent does not satisfy required CLI flags: --enable-tcp=true --multicast-ports=8818,8819",
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
		CLIFlag{Name: "enable-network-events", Value: true},
		CLIFlag{Name: "enable-tcp", Value: true},
	)

	require.Equal(t, []CLIFlag{
		{Name: "enable-network-events", Value: true},
		{Name: "enable-tcp", Value: true},
	}, builder.policytest.CLIFlags)
}
