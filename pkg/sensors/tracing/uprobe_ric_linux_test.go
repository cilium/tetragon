// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows && !nok8s

package tracing

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors"
)

func openTestBinary(t *testing.T) (string, *os.File) {
	t.Helper()
	path, err := os.Executable()
	require.NoError(t, err)
	f, err := os.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { f.Close() })
	return path, f
}

func TestContainerUprobeDigest(t *testing.T) {
	_, binary := openTestBinary(t)
	spec := &v1alpha1.TracingPolicySpec{
		UProbes: []v1alpha1.UProbeSpec{{
			Path:                   "/only/in/container/app",
			Symbols:                []string{"main.main"},
			ResolvePathInContainer: true,
		}},
	}
	polInfo, err := newPolicyInfoFromSpec("ns", "policy", policyfilter.PolicyID(7), spec, nil)
	require.NoError(t, err)

	_, err = containerUprobeSensorBuilder(polInfo, spec, 0)("child", binary)
	require.NoError(t, err)

	spec.UProbes[0].BinaryDigests = []string{"sha256:" + strings.Repeat("0", 64)}
	_, err = containerUprobeSensorBuilder(polInfo, spec, 0)("child", binary)
	var mismatch *DigestMismatchError
	require.ErrorAs(t, err, &mismatch)
}

func TestResolvePathInContainerSensorLoadsHostUprobes(t *testing.T) {
	host, _ := openTestBinary(t)
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

	require.Len(t, sensor.Statuses, 1)
	require.Equal(t, uint32(1), sensor.Statuses[0].HookIdx)
	require.NoError(t, sensor.PreUnloadHook())
}

func TestContainerUprobeSensorBuildsOnlyItsUprobe(t *testing.T) {
	host, binary := openTestBinary(t)
	spec := &v1alpha1.TracingPolicySpec{
		Options: []v1alpha1.OptionSpec{{Name: "disable-uprobe-multi", Value: "1"}},
		UProbes: []v1alpha1.UProbeSpec{
			{Path: host, Symbols: []string{"main.main"}, Selectors: []v1alpha1.KProbeSelector{{}, {}}},
			{Path: "/lib/first.so", Symbols: []string{"main.main"}, ResolvePathInContainer: true,
				Selectors: []v1alpha1.KProbeSelector{{}}},
			{Path: "/lib/second.so", Symbols: []string{"main.main"}, ResolvePathInContainer: true},
		},
	}
	polInfo, err := newPolicyInfoFromSpec("ns", "policy", policyfilter.PolicyID(7), spec, nil)
	require.NoError(t, err)

	built, err := containerUprobeSensorBuilder(polInfo, spec, 2)("child", binary)
	require.NoError(t, err)

	sensor := built.(*sensors.Sensor)
	require.Len(t, sensor.Progs, 1)
	require.Equal(t, uint32(2), sensor.Statuses[0].HookIdx)
	uprobe := sensor.Progs[0].LoaderData.(*genericUprobe)
	require.Equal(t, "/lib/second.so", uprobe.targetPath)
	require.Equal(t, uint32(3), uprobe.loadArgs.config.SelStatsBase)
}

func TestMultiUprobeConsistencyChecksBuiltUprobesOnly(t *testing.T) {
	uprobes := []v1alpha1.UProbeSpec{
		{Path: "/usr/bin/app", Symbols: []string{"main"}},
		{Path: "/usr/bin/app", Offsets: []uint64{0x10}, ResolvePathInContainer: true},
	}
	require.NoError(t, validateMultiUprobeConsistency(uprobes))

	uprobes = append(uprobes, v1alpha1.UProbeSpec{Path: "/usr/bin/app", Offsets: []uint64{0x10}})
	require.Error(t, validateMultiUprobeConsistency(uprobes))
}

func TestContainerUprobeUsesSharedMapsHeldByPolicySensor(t *testing.T) {
	_, binary := openTestBinary(t)
	spec := &v1alpha1.TracingPolicySpec{
		UProbes: []v1alpha1.UProbeSpec{{
			Path:                   "/only/in/container/app",
			Symbols:                []string{"main.main"},
			ResolvePathInContainer: true,
		}},
	}
	polInfo, err := newPolicyInfoFromSpec("", "policy", policyfilter.PolicyID(7), spec, nil)
	require.NoError(t, err)

	parent, err := createResolvePathInContainerSensor(spec, polInfo)
	require.NoError(t, err)
	held := map[string]bool{}
	for _, m := range parent.Maps {
		held[m.Name] = m.IsShared()
	}

	built, err := containerUprobeSensorBuilder(polInfo, spec, 0)("child", binary)
	require.NoError(t, err)
	for _, m := range built.(*sensors.Sensor).Maps {
		require.False(t, m.IsShared(), "map %s", m.Name)
		if slices.Contains(uprobeHeapMaps, m.Name) || strings.HasPrefix(m.Name, "sleepable_") {
			require.True(t, held[m.Name], "map %s is not held by the policy sensor", m.Name)
		}
	}
}
