// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux && (amd64 || arm64)

package selectors

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

func TestUprobeOverridePerSelectorIPDelta(t *testing.T) {
	sels := []v1alpha1.KProbeSelector{
		{MatchActions: []v1alpha1.ActionSelector{{Action: "Override", ArgNewSymbol: "first"}}},
		{MatchActions: []v1alpha1.ActionSelector{{Action: "Override", ArgNewSymbol: "second"}}},
		{MatchActions: []v1alpha1.ActionSelector{{Action: "Override", ArgError: 5}}},
	}

	state, err := InitKernelSelectorState(&KernelSelectorArgs{
		Selectors:              sels,
		IsUprobe:               true,
		OverrideActionIPDeltas: map[int]int64{0: 0x100, 1: 0x200},
	})
	require.NoError(t, err)

	// Each selector gets its own delta, and a selector without a new target
	// keeps the default return value override.
	expected := NewKernelSelectorState(nil, nil, true, 0, nil, nil)
	require.NoError(t, parseOverrideRegs(expected, 0, nil, 0, 0x100))
	require.NoError(t, parseOverrideRegs(expected, 1, nil, 0, 0x200))
	require.NoError(t, parseOverrideRegs(expected, 2, nil, 5, 0))
	require.Equal(t, expected.Regs(), state.Regs())
}

func TestCountOverrideArgNewSymbolAddrOffset(t *testing.T) {
	override := func(action v1alpha1.ActionSelector) v1alpha1.KProbeSelector {
		action.Action = "Override"
		return v1alpha1.KProbeSelector{MatchActions: []v1alpha1.ActionSelector{action}}
	}

	require.Equal(t, 0, CountOverrideArgNewSymbolAddrOffset([]v1alpha1.KProbeSelector{
		override(v1alpha1.ActionSelector{ArgError: 5}),
	}))
	// Targets in different selectors are counted per action.
	require.Equal(t, 1, CountOverrideArgNewSymbolAddrOffset([]v1alpha1.KProbeSelector{
		override(v1alpha1.ActionSelector{ArgError: 5}),
		override(v1alpha1.ActionSelector{ArgNewSymbol: "first"}),
		override(v1alpha1.ActionSelector{ArgNewAddr: 0x1000}),
	}))
	// Conflicting targets in an action that is not the first one are found.
	require.Equal(t, 2, CountOverrideArgNewSymbolAddrOffset([]v1alpha1.KProbeSelector{
		override(v1alpha1.ActionSelector{ArgNewSymbol: "first"}),
		override(v1alpha1.ActionSelector{ArgNewSymbol: "second", ArgNewOffset: 0x10}),
	}))
}
