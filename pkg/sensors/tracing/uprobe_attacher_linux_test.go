// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

// fakeSensorManager records manager calls instead of touching BPF.
type fakeSensorManager struct {
	added     map[string]bool
	enabled   map[string]bool
	calls     []string
	enableErr error
}

func newFakeSensorManager() *fakeSensorManager {
	return &fakeSensorManager{
		added:   map[string]bool{},
		enabled: map[string]bool{},
	}
}

func (m *fakeSensorManager) AddSensor(_ context.Context, name string, _ *sensors.Sensor) error {
	m.calls = append(m.calls, "add:"+name)
	m.added[name] = true
	return nil
}

func (m *fakeSensorManager) EnableSensor(_ context.Context, name string) error {
	m.calls = append(m.calls, "enable:"+name)
	if m.enableErr != nil {
		return m.enableErr
	}
	m.enabled[name] = true
	return nil
}

func (m *fakeSensorManager) RemoveSensor(_ context.Context, name string) error {
	m.calls = append(m.calls, "remove:"+name)
	// RemoveSensor destroys the collection, which also unloads (disables) it.
	delete(m.added, name)
	delete(m.enabled, name)
	return nil
}

// fakeBuilder returns a non-nil empty sensor and records the first resolved path.
func newFakeBuilder(paths *map[string]string) sensorBuilder {
	return func(name string, resolved []resolvedUprobe) (*sensors.Sensor, error) {
		if len(resolved) > 0 {
			(*paths)[name] = resolved[0].attachPath
		}
		return &sensors.Sensor{Name: name}, nil
	}
}

func TestContainerSensorAttacherAttachDetach(t *testing.T) {
	mgr := newFakeSensorManager()
	paths := map[string]string{}
	a := newContainerSensorAttacher("up-pam", 1, mgr, newFakeBuilder(&paths))

	require.NoError(t, a.Attach("podA/c1", []resolvedUprobe{{attachPath: "/procRoot/100/root/lib/libpam.so"}}))
	name := containerSensorName("up-pam", a.generation, "podA/c1")
	require.True(t, mgr.added[name])
	require.True(t, mgr.enabled[name])
	require.Equal(t, "/procRoot/100/root/lib/libpam.so", paths[name])
	require.Equal(t, []string{"add:" + name, "enable:" + name}, mgr.calls)

	a.Detach("podA/c1")
	require.False(t, mgr.enabled[name])
	require.False(t, mgr.added[name])
	require.Equal(t, []string{"add:" + name, "enable:" + name, "remove:" + name}, mgr.calls)

	// detaching an unknown key is a no-op.
	before := len(mgr.calls)
	a.Detach("nope")
	require.Len(t, mgr.calls, before)
}

func TestContainerSensorAttacherEnableFailureCleansUp(t *testing.T) {
	mgr := newFakeSensorManager()
	mgr.enableErr = errors.New("enable boom")
	paths := map[string]string{}
	a := newContainerSensorAttacher("up-pam", 1, mgr, newFakeBuilder(&paths))

	err := a.Attach("podA/c1", []resolvedUprobe{{attachPath: "/procRoot/100/root/lib/a.so"}})
	require.Error(t, err)

	name := containerSensorName("up-pam", a.generation, "podA/c1")
	// the added-but-not-enabled sensor must be removed, and not tracked.
	require.False(t, mgr.added[name], "sensor must be removed after enable failure")
	require.Equal(t, []string{"add:" + name, "enable:" + name, "remove:" + name}, mgr.calls)

	// a failed attach must not be tracked, so a later detach is a no-op.
	callsBefore := len(mgr.calls)
	a.Detach("podA/c1")
	require.Len(t, mgr.calls, callsBefore)
}

func TestContainerSensorName(t *testing.T) {
	// Deterministic and unique per (policy, generation, container key).
	n1 := containerSensorName("up-pam", 1, "podA/c1")
	n2 := containerSensorName("up-pam", 1, "podA/c1")
	require.Equal(t, n1, n2, "must be deterministic for the same inputs")

	require.NotEqual(t, n1, containerSensorName("up-pam", 1, "podA/c2"),
		"different container -> different sensor name")
	require.NotEqual(t, n1, containerSensorName("other", 1, "podA/c1"),
		"different policy -> different sensor name")
	require.NotEqual(t, n1, containerSensorName("up-pam", 2, "podA/c1"),
		"different generation -> different sensor name (re-enable must not collide)")

	// Must contain a recognizable prefix so the sensors are identifiable.
	require.Contains(t, n1, "generic_uprobe")

	// Different keys that could otherwise collide when concatenated naively
	// must still produce distinct names.
	require.NotEqual(t,
		containerSensorName("a", 1, "b/c"),
		containerSensorName("a/b", 1, "c"),
		"key boundaries must not collide")
}

func TestResolvePathInContainerPolicyMapsOwnedByParent(t *testing.T) {
	spec := &v1alpha1.TracingPolicySpec{
		UProbes: []v1alpha1.UProbeSpec{{
			Path:                   "/usr/bin/app",
			Symbols:                []string{"main"},
			ResolvePathInContainer: true,
		}},
	}
	polInfo, err := newPolicyInfoFromSpec("ns", "policy", policyfilter.PolicyID(7), spec, nil)
	require.NoError(t, err)

	parent := &sensors.Sensor{Name: "generic_uprobe", Policy: "policy", Namespace: "ns"}
	initialize := prepareResolvePathInContainerPolicyMaps(parent, polInfo)
	require.NotNil(t, initialize)
	require.Len(t, parent.Maps, 2)
	for _, policyMap := range parent.Maps {
		require.True(t, policyMap.IsOwner(), "parent must own policy-scoped maps")
		require.Equal(t, program.MapTypePolicy, policyMap.Type)
	}

	childProg := program.Builder("child.o", "child", "uprobe/generic_uprobe", "child", "generic_uprobe")
	confUser := polInfo.policyConfMap(childProg)
	statsUser := polInfo.selectorStatsMap(childProg)
	require.False(t, confUser.IsOwner(), "child must only use the parent's policy_conf map")
	require.False(t, statsUser.IsOwner(), "child must only use the parent's selector-stats map")
	require.Empty(t, childProg.MapLoad, "building another child must not reinstall policy mode")

	build := containerUprobeSensorBuilder(polInfo, spec, []*v1alpha1.UProbeSpec{&spec.UProbes[0]})
	require.NotNil(t, build, "child builder must capture the shared parent policyInfo")
}

func TestContainerUprobeDigestVerifiedAgainstResolvedPath(t *testing.T) {
	// The digest must be computed from the resolved in-container path
	// (attachPath), not the in-container spec path, which is invisible in the
	// agent's mount namespace. Point attachPath at a real ELF (the test binary)
	// with a non-matching digest: a DigestMismatchError proves the bytes were
	// read from attachPath. If the code opened spec.Path instead, the open would
	// fail with ENOENT rather than a mismatch.
	realELF, err := os.Executable()
	require.NoError(t, err)

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

	build := containerUprobeSensorBuilder(polInfo, parent, []*v1alpha1.UProbeSpec{&parent.UProbes[0]})
	_, err = build("digest-test", []resolvedUprobe{{targetIndex: 0, attachPath: realELF, fileID: "x"}})

	require.Error(t, err)
	var mismatch *DigestMismatchError
	require.ErrorAs(t, err, &mismatch,
		"digest must be read from the resolved attachPath, yielding a mismatch")
}

func TestContainerUprobeSpecPreservesParentSelectorStatsBase(t *testing.T) {
	parent := &v1alpha1.TracingPolicySpec{
		UProbes: []v1alpha1.UProbeSpec{
			{
				Path:                   "/lib/first.so",
				Symbols:                []string{"first"},
				ResolvePathInContainer: true,
				Selectors:              make([]v1alpha1.KProbeSelector, 2),
			},
			{
				Path:                   "/lib/second.so",
				Symbols:                []string{"second"},
				ResolvePathInContainer: true,
				Selectors:              make([]v1alpha1.KProbeSelector, 1),
			},
		},
	}
	uprobes := []*v1alpha1.UProbeSpec{&parent.UProbes[0], &parent.UProbes[1]}

	child, overrides, err := containerUprobeSpec(parent, uprobes, uprobeSelectorStatsBases(parent), []resolvedUprobe{{
		targetIndex: 1,
		attachPath:  "/proc/self/fd/42",
	}})
	require.NoError(t, err)

	require.Len(t, child.UProbes, 1, "one spec/inode attachment must build one child probe")
	require.Equal(t, "/lib/second.so", child.UProbes[0].Path)
	require.False(t, child.UProbes[0].ResolvePathInContainer)
	require.Equal(t, "/proc/self/fd/42", overrides[0].attachPath)
	require.Equal(t, uint32(2), overrides[0].selectorStatsBase,
		"the child-local spec must retain its index in the parent policy stats map")
}
