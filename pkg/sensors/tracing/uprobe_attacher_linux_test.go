// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

// fakeSensors records what the attacher does instead of loading BPF.
type fakeSensors struct {
	calls   []string
	paths   map[string]string
	loadErr error
}

func newFakeSensors() *fakeSensors {
	return &fakeSensors{paths: map[string]string{}}
}

func (f *fakeSensors) builder() sensorBuilder {
	return func(name, attachPath string) (loadedSensor, error) {
		f.paths[name] = attachPath
		return &fakeSensor{name: name, owner: f}, nil
	}
}

type fakeSensor struct {
	name  string
	owner *fakeSensors
}

func (s *fakeSensor) Load(string) error {
	s.owner.calls = append(s.owner.calls, "load:"+s.name)
	return s.owner.loadErr
}

func (s *fakeSensor) Destroy(bool) error {
	s.owner.calls = append(s.owner.calls, "destroy:"+s.name)
	return nil
}

func TestContainerSensorAttacherAttachDetach(t *testing.T) {
	f := newFakeSensors()
	a := newContainerSensorAttacher("up-pam", 1, "/sys/fs/bpf/tetragon", f.builder())

	require.NoError(t, a.Attach("podA/c1", "/procRoot/100/root/lib/libpam.so"))
	name := containerSensorName("up-pam", a.generation, "podA/c1")
	require.Equal(t, "/procRoot/100/root/lib/libpam.so", f.paths[name])
	require.Equal(t, []string{"load:" + name}, f.calls)

	a.Detach("podA/c1")
	require.Equal(t, []string{"load:" + name, "destroy:" + name}, f.calls)

	// detaching an unknown key, or the same key twice, is a no-op.
	a.Detach("podA/c1")
	a.Detach("nope")
	require.Len(t, f.calls, 2)
}

func TestContainerSensorAttacherLoadFailureDestroysSensor(t *testing.T) {
	f := newFakeSensors()
	f.loadErr = errors.New("load boom")
	a := newContainerSensorAttacher("up-pam", 1, "/sys/fs/bpf/tetragon", f.builder())

	require.Error(t, a.Attach("podA/c1", "/procRoot/100/root/lib/a.so"))

	name := containerSensorName("up-pam", a.generation, "podA/c1")
	require.Equal(t, []string{"load:" + name, "destroy:" + name}, f.calls,
		"a sensor that failed to load must release its resources")

	// a failed attach must not be tracked, so a later detach is a no-op.
	a.Detach("podA/c1")
	require.Len(t, f.calls, 2)
}

func TestContainerSensorName(t *testing.T) {
	// Deterministic and unique per (policy, generation, container key).
	n1 := containerSensorName("up-pam", 1, "podA/c1")
	require.Equal(t, n1, containerSensorName("up-pam", 1, "podA/c1"), "must be deterministic")

	require.NotEqual(t, n1, containerSensorName("up-pam", 1, "podA/c2"),
		"different container -> different sensor name")
	require.NotEqual(t, n1, containerSensorName("other", 1, "podA/c1"),
		"different policy -> different sensor name")
	require.NotEqual(t, n1, containerSensorName("up-pam", 2, "podA/c1"),
		"different generation -> different sensor name (re-enable must not collide)")
	require.Contains(t, n1, "generic_uprobe")

	// Keys that would collide when concatenated naively must not.
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
	prepareResolvePathInContainerPolicyMaps(parent, polInfo)
	require.Len(t, parent.Maps, 2)
	initializers := 0
	for _, policyMap := range parent.Maps {
		require.True(t, policyMap.IsOwner(), "parent must own policy-scoped maps")
		require.Equal(t, program.MapTypePolicy, policyMap.Type)
		if policyMap.Validate != nil {
			initializers++
		}
	}
	require.Equal(t, 1, initializers,
		"policy_conf must be initialized as the map is created, since the parent loads no programs")

	childProg := program.Builder("child.o", "child", "uprobe/generic_uprobe", "child", "generic_uprobe")
	require.False(t, polInfo.policyConfMap(childProg).IsOwner(), "child must only use the parent's policy_conf map")
	require.False(t, polInfo.selectorStatsMap(childProg).IsOwner(), "child must only use the parent's selector-stats map")
	require.Empty(t, childProg.MapLoad, "building another child must not reinstall policy mode")
}

// The digest must be computed from the resolved in-container path. Pointing it
// at a real ELF with a non-matching digest proves the bytes were read from
// there: opening the spec path instead would fail with ENOENT.
func TestContainerUprobeDigestVerifiedAgainstResolvedPath(t *testing.T) {
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

	build := containerUprobeSensorBuilder(polInfo, parent, &parent.UProbes[0])
	_, err = build("digest-test", realELF)

	var mismatch *DigestMismatchError
	require.ErrorAs(t, err, &mismatch,
		"the digest must be read from the resolved path, yielding a mismatch")
}

// The child spec keeps the in-container Path, and drops the flag so the child
// sensor actually attaches.
func TestContainerUprobeSpecKeepsPathAndClearsFlag(t *testing.T) {
	parent := &v1alpha1.TracingPolicySpec{
		Options: []v1alpha1.OptionSpec{{Name: "disable-uprobe-multi", Value: "1"}},
		UProbes: []v1alpha1.UProbeSpec{{
			Path:                   "/lib/first.so",
			Symbols:                []string{"first"},
			ResolvePathInContainer: true,
		}},
	}

	child := containerUprobeSpec(parent, &parent.UProbes[0])

	require.Len(t, child.UProbes, 1)
	require.Equal(t, "/lib/first.so", child.UProbes[0].Path)
	require.False(t, child.UProbes[0].ResolvePathInContainer)
	require.Equal(t, parent.Options, child.Options, "child must inherit the policy options")
	require.True(t, parent.UProbes[0].ResolvePathInContainer, "the parent spec must be left untouched")
}
