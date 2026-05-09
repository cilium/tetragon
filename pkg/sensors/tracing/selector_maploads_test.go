// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/selectors"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

func mapLoadNames(loads []*program.MapLoad) []string {
	names := make([]string, 0, len(loads))
	for _, load := range loads {
		names = append(names, load.Name)
	}
	return names
}

func TestSelectorsMaploadsSkipsEmptySelectorMaps(t *testing.T) {
	state, err := selectors.InitKernelSelectorState(&selectors.KernelSelectorArgs{
		Selectors: []v1alpha1.KProbeSelector{{}},
	})
	require.NoError(t, err)

	require.Equal(t, []string{"filter_map"}, mapLoadNames(selectorsMaploads(state, 0)))
}

func TestSelectorsMaploadsIncludesOnlyUsedStringMaps(t *testing.T) {
	state, err := selectors.InitKernelSelectorState(&selectors.KernelSelectorArgs{
		Selectors: []v1alpha1.KProbeSelector{{
			MatchArgs: []v1alpha1.ArgSelector{{
				Index:    0,
				Operator: "Equal",
				Values:   []string{"bash"},
			}},
		}},
		Args: []v1alpha1.KProbeArg{{
			Index: 0,
			Type:  "string",
		}},
	})
	require.NoError(t, err)

	names := mapLoadNames(selectorsMaploads(state, 0))
	require.Contains(t, names, "filter_map")

	var stringMaps int
	for _, name := range names {
		if strings.HasPrefix(name, "string_maps_") {
			stringMaps++
		}
		require.NotContains(t, []string{"argfilter_maps", "addr4lpm_maps", "addr6lpm_maps"}, name)
	}
	require.Equal(t, 1, stringMaps)
}
