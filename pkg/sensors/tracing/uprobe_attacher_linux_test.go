// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors"
)

// fakeSensorManager records manager calls instead of touching BPF.
type fakeSensorManager struct {
	added      map[string]bool
	enabled    map[string]bool
	calls      []string
	enableErr  error
	enabledHad map[string]bool
}

func newFakeSensorManager() *fakeSensorManager {
	return &fakeSensorManager{
		added:      map[string]bool{},
		enabled:    map[string]bool{},
		enabledHad: map[string]bool{},
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
	m.enabledHad[name] = true
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
	return func(_, _, name string, resolved []resolvedUprobe, _ policyfilter.PolicyID, _ *v1alpha1.TracingPolicySpec, _ []*v1alpha1.UProbeSpec) (*sensors.Sensor, error) {
		if len(resolved) > 0 {
			(*paths)[name] = resolved[0].attachPath
		}
		return &sensors.Sensor{Name: name}, nil
	}
}

func TestContainerSensorAttacherAttachDetach(t *testing.T) {
	mgr := newFakeSensorManager()
	paths := map[string]string{}
	a := newContainerSensorAttacher("up-pam", "up-pam", "", 1, policyfilter.NoFilterID, nil, []*v1alpha1.UProbeSpec{{Symbols: []string{"pam_authenticate"}}}, mgr, newFakeBuilder(&paths))

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
	a := newContainerSensorAttacher("up-pam", "up-pam", "", 1, policyfilter.NoFilterID, nil, []*v1alpha1.UProbeSpec{{Symbols: []string{"s"}}}, mgr, newFakeBuilder(&paths))

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
