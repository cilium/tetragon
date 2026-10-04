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
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

func TestResolvePathInContainerSensor(t *testing.T) {
	spec := ricSpec()
	polInfo, err := newPolicyInfoFromSpec("ns", "policy", policyfilter.PolicyID(7), spec, nil)
	require.NoError(t, err)

	sensor, err := createResolvePathInContainerSensor(spec, polInfo)
	require.NoError(t, err)

	require.Empty(t, sensor.Progs)
	require.False(t, sensor.IsEmpty(), "the policy mode and stats come from its maps")
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

	_, err = containerUprobeSensorBuilder(polInfo, parent, 0)("digest-test", binary)

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

	_, err = containerUprobeSensorBuilder(polInfo, parent, 0)("no-digest-test", binary)
	require.NoError(t, err)
}

func TestResolvePathInContainerSensorLoadsHostUprobes(t *testing.T) {
	host, err := os.Executable()
	require.NoError(t, err)
	spec := &v1alpha1.TracingPolicySpec{
		UProbes: []v1alpha1.UProbeSpec{
			{Path: "/only/in/container/app", Symbols: []string{"main"}, ResolvePathInContainer: true},
			{Path: host, Symbols: []string{"main.main"}},
		},
	}
	polInfo, err := newPolicyInfoFromSpec("ns", "policy", policyfilter.PolicyID(7), spec, nil)
	require.NoError(t, err)

	sensor, err := createResolvePathInContainerSensor(spec, polInfo)
	require.NoError(t, err)

	require.NotEmpty(t, sensor.Progs)
	require.Len(t, sensor.Statuses, 1)
	require.Equal(t, uint32(1), sensor.Statuses[0].HookIdx)
	require.NoError(t, sensor.PreUnloadHook())
	// The host uprobe's program owns the policy maps.
	childProg := program.Builder("child.o", "child", "uprobe/generic_uprobe", "child", "generic_uprobe")
	require.False(t, polInfo.policyConfMap(childProg).IsOwner())
}

func TestContainerUprobeSensorBuildsOnlyItsUprobe(t *testing.T) {
	realELF, err := os.Executable()
	require.NoError(t, err)
	binary, err := os.Open(realELF)
	require.NoError(t, err)
	defer binary.Close()
	parent := &v1alpha1.TracingPolicySpec{
		Options: []v1alpha1.OptionSpec{{Name: "disable-uprobe-multi", Value: "1"}},
		UProbes: []v1alpha1.UProbeSpec{
			{Path: realELF, Symbols: []string{"main.main"}, Selectors: []v1alpha1.KProbeSelector{{}, {}}},
			{Path: "/lib/first.so", Symbols: []string{"main.main"}, ResolvePathInContainer: true,
				Selectors: []v1alpha1.KProbeSelector{{}}},
			{Path: "/lib/second.so", Symbols: []string{"main.main"}, ResolvePathInContainer: true},
		},
	}
	polInfo, err := newPolicyInfoFromSpec("ns", "policy", policyfilter.PolicyID(7), parent, nil)
	require.NoError(t, err)

	built, err := containerUprobeSensorBuilder(polInfo, parent, 2)("child", binary)
	require.NoError(t, err)

	sensor := built.(*sensors.Sensor)
	require.Len(t, sensor.Statuses, 1)
	require.Equal(t, uint32(2), sensor.Statuses[0].HookIdx)
	require.Len(t, sensor.Progs, 1)
	uprobe := sensor.Progs[0].LoaderData.(*genericUprobe)
	require.Equal(t, "/lib/second.so", uprobe.targetPath)
	// Its selector stats follow those of every uprobe before it.
	require.Equal(t, uint32(3), uprobe.loadArgs.config.SelStatsBase)
}

func TestContainerUprobeSpec(t *testing.T) {
	parent := &v1alpha1.TracingPolicySpec{
		Options: []v1alpha1.OptionSpec{{Name: "disable-uprobe-multi", Value: "1"}},
		UProbes: []v1alpha1.UProbeSpec{
			{Path: "/bin/host", Symbols: []string{"main"}},
			{
				Path:                   "/lib/first.so",
				Symbols:                []string{"first"},
				ResolvePathInContainer: true,
				Selectors:              []v1alpha1.KProbeSelector{{}},
			},
		},
	}

	child := containerUprobeSpec(parent, 1)

	// Every uprobe is kept, so each keeps its index and selector offset.
	require.Len(t, child.UProbes, 2)
	require.Equal(t, "/lib/first.so", child.UProbes[1].Path)
	require.Equal(t, parent.Options, child.Options)
	require.NotSame(t, &parent.UProbes[1].Selectors[0], &child.UProbes[1].Selectors[0])
}

func TestMultiUprobeConsistencyChecksBuiltUprobesOnly(t *testing.T) {
	uprobes := []v1alpha1.UProbeSpec{
		{Path: "/usr/bin/app", Symbols: []string{"main"}},
		{Path: "/usr/bin/app", Offsets: []uint64{0x10}, ResolvePathInContainer: true},
		{Path: "/usr/bin/app", Symbols: []string{"main"}, ResolvePathInContainer: true},
	}

	// The host uprobes and each resolvePathInContainer uprobe load in
	// sensors of their own, so a shared path does not tie them together.
	require.NoError(t, validateMultiUprobeConsistency(uprobes))

	uprobes = append(uprobes, v1alpha1.UProbeSpec{Path: "/usr/bin/app", Offsets: []uint64{0x10}})
	require.ErrorContains(t, validateMultiUprobeConsistency(uprobes),
		"uprobe[3] uses offsets while uprobe[0] uses symbols")
}
