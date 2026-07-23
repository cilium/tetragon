// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package sensors

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

type orderedLifecycleSensor struct {
	loaded            atomic.Bool
	preDisableStarted chan struct{}
	allowPreDisable   chan struct{}
	unloadStarted     chan struct{}
}

func newOrderedLifecycleSensor() *orderedLifecycleSensor {
	s := &orderedLifecycleSensor{
		preDisableStarted: make(chan struct{}),
		allowPreDisable:   make(chan struct{}),
		unloadStarted:     make(chan struct{}),
	}
	s.loaded.Store(true)
	return s
}

func (s *orderedLifecycleSensor) GetName() string                  { return "ordered" }
func (s *orderedLifecycleSensor) IsLoaded() bool                   { return s.loaded.Load() }
func (s *orderedLifecycleSensor) Load(string) error                { s.loaded.Store(true); return nil }
func (s *orderedLifecycleSensor) TotalMemlock() uint64             { return 0 }
func (s *orderedLifecycleSensor) Overhead() ([]ProgOverhead, bool) { return nil, false }
func (s *orderedLifecycleSensor) DisableNotAllowed() string        { return "" }
func (s *orderedLifecycleSensor) PreDisable() error {
	close(s.preDisableStarted)
	<-s.allowPreDisable
	return nil
}
func (s *orderedLifecycleSensor) Unload(bool) error {
	close(s.unloadStarted)
	s.loaded.Store(false)
	return nil
}
func (s *orderedLifecycleSensor) Destroy(bool) error {
	s.loaded.Store(false)
	return nil
}

// reentrantDestroySensor models a sensor teardown hook which calls back into
// the manager's collection map, as RIC parent teardown does through
// RemoveSensor for its children.
type reentrantDestroySensor struct {
	h         *handler
	reentered bool
}

type callbackDestroySensor struct {
	name    string
	destroy func() error
}

func (s *callbackDestroySensor) GetName() string                  { return s.name }
func (s *callbackDestroySensor) IsLoaded() bool                   { return true }
func (s *callbackDestroySensor) Load(string) error                { return nil }
func (s *callbackDestroySensor) Unload(bool) error                { return nil }
func (s *callbackDestroySensor) TotalMemlock() uint64             { return 0 }
func (s *callbackDestroySensor) Overhead() ([]ProgOverhead, bool) { return nil, false }
func (s *callbackDestroySensor) DisableNotAllowed() string        { return "" }
func (s *callbackDestroySensor) Destroy(bool) error               { return s.destroy() }

func (s *reentrantDestroySensor) GetName() string                  { return "reentrant" }
func (s *reentrantDestroySensor) IsLoaded() bool                   { return true }
func (s *reentrantDestroySensor) Load(string) error                { return nil }
func (s *reentrantDestroySensor) Unload(bool) error                { return nil }
func (s *reentrantDestroySensor) TotalMemlock() uint64             { return 0 }
func (s *reentrantDestroySensor) Overhead() ([]ProgOverhead, bool) { return nil, false }
func (s *reentrantDestroySensor) DisableNotAllowed() string        { return "" }
func (s *reentrantDestroySensor) Destroy(bool) error {
	s.h.collections.mu.Lock()
	s.reentered = true
	s.h.collections.mu.Unlock()
	return nil
}

func TestRemoveAllSensorsDestroysOutsideCollectionLock(t *testing.T) {
	h := &handler{collections: newCollectionMap()}
	sensor := &reentrantDestroySensor{h: h}
	h.collections.c[collectionKey{name: sensor.GetName(), domain: sensorsDomain}] = &collection{
		name:    sensor.GetName(),
		sensors: []SensorIface{sensor},
	}

	done := make(chan struct{})
	go func() {
		removeAllSensors(h, true)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("removeAllSensors held collections.mu while destroying a reentrant sensor")
	}
	require.True(t, sensor.reentered, "destroy must have taken collections.mu itself")
	require.Empty(t, h.collections.c)
}

func TestRemoveAllSensorsKeepsPolicyChildrenDiscoverable(t *testing.T) {
	h := &handler{collections: newCollectionMap()}
	var order []string
	child := &callbackDestroySensor{name: "child", destroy: func() error {
		order = append(order, "child")
		return nil
	}}
	parent := &callbackDestroySensor{name: "parent", destroy: func() error {
		if err := h.removeSensor(&sensorRemove{ctx: context.Background(), name: child.name, unpin: true}); err != nil {
			return err
		}
		order = append(order, "parent")
		return nil
	}}

	h.collections.c[collectionKey{name: child.name, domain: sensorsDomain}] = &collection{
		name: child.name, sensors: []SensorIface{child},
	}
	h.collections.c[collectionKey{name: parent.name, domain: "test"}] = &collection{
		name: parent.name, tracingpolicy: &v1alpha1.TracingPolicy{}, sensors: []SensorIface{parent},
	}

	removeAllSensors(h, true)

	require.Equal(t, []string{"child", "parent"}, order,
		"policy teardown must be able to remove its internal children before the parent")
	require.Empty(t, h.collections.c)
}

func TestDisableRunsPreDisableBeforeLoadLock(t *testing.T) {
	h := &handler{collections: newCollectionMap()}
	sensor := newOrderedLifecycleSensor()
	ck := collectionKey{name: "policy", domain: "test"}
	h.collections.c[ck] = &collection{
		name:    ck.name,
		state:   EnabledState,
		sensors: []SensorIface{sensor},
	}

	// Model a child EnableSensor operation which already owns the global load
	// lock. Policy cleanup must start before disable waits for this lock.
	h.muLoad.Lock()
	done := make(chan error, 1)
	go func() {
		done <- h.configureTracingPolicy(ck, nil, new(false))
	}()

	select {
	case <-sensor.preDisableStarted:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("disable waited for muLoad before running the pre-disable hook")
	}
	close(sensor.allowPreDisable)
	select {
	case <-sensor.unloadStarted:
		t.Fatal("sensor unload started while muLoad was held")
	case <-time.After(25 * time.Millisecond):
	}
	h.muLoad.Unlock()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("disable did not finish after muLoad was released")
	}
}
