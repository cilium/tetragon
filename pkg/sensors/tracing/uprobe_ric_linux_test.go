// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows && !nok8s

package tracing

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

func TestResolvePathInContainerSensor(t *testing.T) {
	spec := ricSpec()
	polInfo, err := newPolicyInfoFromSpec("ns", "policy", policyfilter.PolicyID(7), spec, nil)
	require.NoError(t, err)

	sensor, err := createResolvePathInContainerSensor(spec, &spec.UProbes[0], polInfo)
	require.NoError(t, err)

	require.Empty(t, sensor.Progs)
	require.Len(t, sensor.Maps, 2)
	for _, m := range sensor.Maps {
		require.True(t, m.IsOwner())
		require.Equal(t, program.MapTypePolicy, m.Type)
	}
	require.NotNil(t, sensor.PostLoadHook)
	require.Nil(t, sensor.PostUnloadHook)
	require.NoError(t, sensor.PreUnloadHook())

	childProg := program.Builder("child.o", "child", "uprobe/generic_uprobe", "child", "generic_uprobe")
	require.False(t, polInfo.policyConfMap(childProg).IsOwner())
	require.False(t, polInfo.selectorStatsMap(childProg).IsOwner())
	require.Empty(t, childProg.MapLoad)
}

func TestContainerUprobeDigestVerifiedAgainstResolvedBinary(t *testing.T) {
	realELF, err := os.Executable()
	require.NoError(t, err)
	binary, err := os.Open(realELF)
	require.NoError(t, err)
	defer binary.Close()

	parent := &v1alpha1.TracingPolicySpec{
		UProbes: []v1alpha1.UProbeSpec{{
			Path:                   "/only/in/container/app",
			Symbols:                []string{"main"},
			ResolvePathInContainer: true,
			BinaryDigests: []string{
				"sha256:0000000000000000000000000000000000000000000000000000000000000000",
			},
		}},
	}
	polInfo, err := newPolicyInfoFromSpec("ns", "policy", policyfilter.PolicyID(7), parent, nil)
	require.NoError(t, err)

	_, err = containerUprobeSensorBuilder(polInfo, parent, &parent.UProbes[0])("digest-test", binary)

	var mismatch *DigestMismatchError
	require.ErrorAs(t, err, &mismatch)
}

func TestContainerUprobeWithoutDigestsBuilds(t *testing.T) {
	realELF, err := os.Executable()
	require.NoError(t, err)
	binary, err := os.Open(realELF)
	require.NoError(t, err)
	defer binary.Close()

	parent := &v1alpha1.TracingPolicySpec{
		UProbes: []v1alpha1.UProbeSpec{{
			Path:                   "/only/in/container/app",
			Symbols:                []string{"main.main"},
			ResolvePathInContainer: true,
		}},
	}
	polInfo, err := newPolicyInfoFromSpec("ns", "policy", policyfilter.PolicyID(7), parent, nil)
	require.NoError(t, err)

	_, err = containerUprobeSensorBuilder(polInfo, parent, &parent.UProbes[0])("no-digest-test", binary)
	require.NoError(t, err)
}

func TestContainerUprobeSpec(t *testing.T) {
	parent := &v1alpha1.TracingPolicySpec{
		Options: []v1alpha1.OptionSpec{{Name: "disable-uprobe-multi", Value: "1"}},
		UProbes: []v1alpha1.UProbeSpec{{
			Path:                   "/lib/first.so",
			Symbols:                []string{"first"},
			ResolvePathInContainer: true,
			Selectors:              []v1alpha1.KProbeSelector{{}},
		}},
	}

	child := containerUprobeSpec(parent, &parent.UProbes[0])

	require.Len(t, child.UProbes, 1)
	require.Equal(t, "/lib/first.so", child.UProbes[0].Path)
	require.Equal(t, parent.Options, child.Options)
	require.NotSame(t, &parent.UProbes[0].Selectors[0], &child.UProbes[0].Selectors[0])
}
