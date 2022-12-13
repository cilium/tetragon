// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package sensors

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/sensors/program"

	"github.com/stretchr/testify/assert"
)

type dummyHandler struct {
	s *Sensor
	e error
}

func (d *dummyHandler) SpecHandler(raw interface{}) (*Sensor, error) {
	return d.s, d.e
}

// TestAddPolicy tests the addition of a policy with a dummy sensor
func TestAddPolicy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	RegisterSpecHandlerAtInit("dummy", &dummyHandler{s: &Sensor{Name: "dummy-sensor"}})
	t.Cleanup(func() {
		delete(registeredSpecHandlers, "dummy")
	})

	policy := v1alpha1.TracingPolicy{}
	mgr, err := StartSensorManager("", "", "")
	assert.NoError(t, err)
	t.Cleanup(func() {
		if err := mgr.StopSensorManager(ctx); err != nil {
			panic("failed to stop sensor manager")
		}
	})
	err = mgr.AddTracingPolicy(ctx, "test-policy", &policy)
	assert.NoError(t, err)
	l, err := mgr.ListSensors(ctx)
	assert.NoError(t, err)
	assert.Equal(t, []SensorStatus{{Name: "dummy-sensor", Enabled: true}}, *l)
}

// TestAddPolicies tests the addition of a policy with two dummy sensors
func TestAddPolicies(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	RegisterSpecHandlerAtInit("dummy1", &dummyHandler{s: &Sensor{Name: "dummy-sensor1"}})
	RegisterSpecHandlerAtInit("dummy2", &dummyHandler{s: &Sensor{Name: "dummy-sensor2"}})
	t.Cleanup(func() {
		delete(registeredSpecHandlers, "dummy1")
		delete(registeredSpecHandlers, "dummy2")
	})

	policy := v1alpha1.TracingPolicy{}
	mgr, err := StartSensorManager("", "", "")
	assert.NoError(t, err)
	t.Cleanup(func() {
		if err := mgr.StopSensorManager(ctx); err != nil {
			panic("failed to stop sensor manager")
		}
	})
	err = mgr.AddTracingPolicy(ctx, "test-policy", &policy)
	assert.NoError(t, err)
	l, err := mgr.ListSensors(ctx)
	assert.NoError(t, err)
	assert.ElementsMatch(t, []SensorStatus{
		{Name: "dummy-sensor1", Enabled: true},
		{Name: "dummy-sensor2", Enabled: true},
	}, *l)
}

// TestAddPolicySpecError tests the addition of a policy where a spec fails to load
func TestAddPolicySpecError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	RegisterSpecHandlerAtInit("dummy", &dummyHandler{s: &Sensor{Name: "dummy-sensor"}})
	RegisterSpecHandlerAtInit("spec-fail", &dummyHandler{e: errors.New("spec load is expected to fail: failed")})
	t.Cleanup(func() {
		delete(registeredSpecHandlers, "dummy")
		delete(registeredSpecHandlers, "spec-fail")
	})

	policy := v1alpha1.TracingPolicy{}
	mgr, err := StartSensorManager("", "", "")
	assert.NoError(t, err)
	t.Cleanup(func() {
		if err := mgr.StopSensorManager(ctx); err != nil {
			panic("failed to stop sensor manager")
		}
	})
	err = mgr.AddTracingPolicy(ctx, "test-policy", &policy)
	assert.NotNil(t, err)
	t.Logf("got error (as expected): %s", err)
	l, err := mgr.ListSensors(ctx)
	assert.NoError(t, err)
	assert.Equal(t, []SensorStatus{}, *l)
}

// TestAddPolicyLoadError tests the addition of a policy where the sensor is expected to fail
func TestAddPolicyLoadError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	RegisterSpecHandlerAtInit("dummy", &dummyHandler{s: &Sensor{Name: "dummy-sensor"}})
	RegisterSpecHandlerAtInit("load-fail", &dummyHandler{s: &Sensor{
		Name:  "dummy-sensor",
		Progs: []*program.Program{{Name: "bpf-program-that-does-not-exist"}},
	}})
	t.Cleanup(func() {
		delete(registeredSpecHandlers, "dummy")
		delete(registeredSpecHandlers, "load-fail")
	})

	policy := v1alpha1.TracingPolicy{}
	mgr, err := StartSensorManager("", "", "")
	assert.NoError(t, err)
	t.Cleanup(func() {
		if err := mgr.StopSensorManager(ctx); err != nil {
			panic("failed to stop sensor manager")
		}
	})
	err = mgr.AddTracingPolicy(ctx, "test-policy", &policy)
	assert.NotNil(t, err)
	t.Logf("got error (as expected): %s", err)
	l, err := mgr.ListSensors(ctx)
	assert.NoError(t, err)
	assert.Equal(t, []SensorStatus{}, *l)
}
