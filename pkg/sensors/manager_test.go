// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package sensors

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/tracingpolicy"

	"github.com/stretchr/testify/assert"
)

type dummyHandler struct {
	s *Sensor
	e error
}

func (d *dummyHandler) PolicyHandler(_ tracingpolicy.TracingPolicy, _ policyfilter.PolicyID) (*Sensor, error) {
	return d.s, d.e
}

// TestAddPolicy tests the addition of a policy with a dummy sensor
func TestAddPolicy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	RegisterPolicyHandlerAtInit("dummy", &dummyHandler{s: &Sensor{Name: "dummy-sensor"}})
	t.Cleanup(func() {
		delete(registeredPolicyHandlers, "dummy")
	})

	policy := v1alpha1.TracingPolicy{}
	mgr, err := StartSensorManager("", "", "", nil)
	assert.NoError(t, err)
	t.Cleanup(func() {
		if err := mgr.StopSensorManager(ctx); err != nil {
			panic("failed to stop sensor manager")
		}
	})
	policy.ObjectMeta.Name = "test-policy"
	err = mgr.AddTracingPolicy(ctx, &policy)
	assert.NoError(t, err)
	l, err := mgr.ListSensors(ctx)
	assert.NoError(t, err)
	assert.Equal(t, []SensorStatus{{Name: "dummy-sensor", Enabled: true, Collection: "test-policy (object:0/) (type:/)"}}, *l)
}

// TestAddPolicies tests the addition of a policy with two dummy sensors
func TestAddPolicies(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	RegisterPolicyHandlerAtInit("dummy1", &dummyHandler{s: &Sensor{Name: "dummy-sensor1"}})
	RegisterPolicyHandlerAtInit("dummy2", &dummyHandler{s: &Sensor{Name: "dummy-sensor2"}})
	t.Cleanup(func() {
		delete(registeredPolicyHandlers, "dummy1")
		delete(registeredPolicyHandlers, "dummy2")
	})

	policy := v1alpha1.TracingPolicy{}
	mgr, err := StartSensorManager("", "", "", nil)
	assert.NoError(t, err)
	t.Cleanup(func() {
		if err := mgr.StopSensorManager(ctx); err != nil {
			panic("failed to stop sensor manager")
		}
	})
	policy.ObjectMeta.Name = "test-policy"
	err = mgr.AddTracingPolicy(ctx, &policy)
	assert.NoError(t, err)
	l, err := mgr.ListSensors(ctx)
	assert.NoError(t, err)
	assert.ElementsMatch(t, []SensorStatus{
		{Name: "dummy-sensor1", Enabled: true, Collection: "test-policy (object:0/) (type:/)"},
		{Name: "dummy-sensor2", Enabled: true, Collection: "test-policy (object:0/) (type:/)"},
	}, *l)
}

// TestAddPolicySpecError tests the addition of a policy where a spec fails to load
func TestAddPolicySpecError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	RegisterPolicyHandlerAtInit("dummy", &dummyHandler{s: &Sensor{Name: "dummy-sensor"}})
	RegisterPolicyHandlerAtInit("spec-fail", &dummyHandler{e: errors.New("spec load is expected to fail: failed")})
	t.Cleanup(func() {
		delete(registeredPolicyHandlers, "dummy")
		delete(registeredPolicyHandlers, "spec-fail")
	})

	policy := v1alpha1.TracingPolicy{}
	mgr, err := StartSensorManager("", "", "", nil)
	assert.NoError(t, err)
	t.Cleanup(func() {
		if err := mgr.StopSensorManager(ctx); err != nil {
			panic("failed to stop sensor manager")
		}
	})
	policy.ObjectMeta.Name = "test-policy"
	err = mgr.AddTracingPolicy(ctx, &policy)
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

	RegisterPolicyHandlerAtInit("dummy", &dummyHandler{s: &Sensor{Name: "dummy-sensor"}})
	RegisterPolicyHandlerAtInit("load-fail", &dummyHandler{s: &Sensor{
		Name:  "dummy-sensor",
		Progs: []*program.Program{{Name: "bpf-program-that-does-not-exist"}},
	}})
	t.Cleanup(func() {
		delete(registeredPolicyHandlers, "dummy")
		delete(registeredPolicyHandlers, "load-fail")
	})

	policy := v1alpha1.TracingPolicy{}
	mgr, err := StartSensorManager("", "", "", nil)
	assert.NoError(t, err)
	t.Cleanup(func() {
		if err := mgr.StopSensorManager(ctx); err != nil {
			panic("failed to stop sensor manager")
		}
	})
	policy.ObjectMeta.Name = "test-policy"
	err = mgr.AddTracingPolicy(ctx, &policy)
	assert.NotNil(t, err)
	t.Logf("got error (as expected): %s", err)
	l, err := mgr.ListSensors(ctx)
	assert.NoError(t, err)
	assert.Equal(t, []SensorStatus{}, *l)
}
