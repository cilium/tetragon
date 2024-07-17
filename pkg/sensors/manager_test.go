// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package sensors

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/tracingpolicy"

	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type dummyHandler struct {
	s SensorIface
	e error
}

func (d *dummyHandler) PolicyHandler(_ tracingpolicy.TracingPolicy, _ policyfilter.PolicyID) (SensorIface, error) {
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
	mgr, err := StartSensorManager("", nil)
	assert.NoError(t, err)
	t.Cleanup(func() {
		if err := mgr.StopSensorManager(ctx); err != nil {
			t.Fatal("failed to stop sensor manager")
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
	mgr, err := StartSensorManager("", nil)
	assert.NoError(t, err)
	t.Cleanup(func() {
		if err := mgr.StopSensorManager(ctx); err != nil {
			t.Fatal("failed to stop sensor manager")
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
	mgr, err := StartSensorManager("", nil)
	assert.NoError(t, err)
	t.Cleanup(func() {
		if err := mgr.StopSensorManager(ctx); err != nil {
			t.Fatal("failed to stop sensor manager")
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
	mgr, err := StartSensorManager("", nil)
	assert.NoError(t, err)
	t.Cleanup(func() {
		if err := mgr.StopSensorManager(ctx); err != nil {
			t.Fatal("failed to stop sensor manager")
		}
	})
	policy.ObjectMeta.Name = "test-policy"
	addError := mgr.AddTracingPolicy(ctx, &policy)
	assert.NotNil(t, addError)
	t.Logf("got error (as expected): %s", addError)

	l, err := mgr.ListTracingPolicies(ctx)
	assert.NoError(t, err)
	assert.Len(t, l.Policies, 1)
	assert.Equal(t, LoadErrorState.ToTetragonState(), l.Policies[0].State)
	assert.Equal(t, addError.Error(), l.Policies[0].Error)
}

func TestPolicyFilterDisabled(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	handler, err := newHandler(policyfilter.DisabledState(), newCollectionMap(), "")
	assert.NoError(t, err)
	mgr, err := startSensorManager(handler, handler.collections, nil)
	assert.NoError(t, err)
	defer mgr.StopSensorManager(ctx)

	policy := v1alpha1.TracingPolicy{}

	// normal policy should succeed
	policyName := "test-policy"
	policyNamespace := ""
	policy.ObjectMeta.Name = policyName
	err = mgr.AddTracingPolicy(ctx, &policy)
	require.NoError(t, err, fmt.Sprintf("Add tracing policy failed with error: %v", err))
	err = mgr.DeleteTracingPolicy(ctx, policyName, policyNamespace)
	require.NoError(t, err)
	err = mgr.AddTracingPolicy(ctx, &policy)
	require.NoError(t, err)
	err = mgr.DeleteTracingPolicy(ctx, policyName, policyNamespace)
	require.NoError(t, err)

	// namespaced policy with disabled state should fail
	namespacedPolicy := v1alpha1.TracingPolicyNamespaced{}
	policy.ObjectMeta.Name = policyName
	namespacedPolicy.ObjectMeta.Name = policyName
	namespacedPolicy.ObjectMeta.Namespace = "namespace"
	err = mgr.AddTracingPolicy(ctx, &namespacedPolicy)
	require.Error(t, err)

	// policy with pod selector should fail
	policy.Spec.PodSelector = &slimv1.LabelSelector{
		MatchExpressions: []slimv1.LabelSelectorRequirement{{
			Key:      "app",
			Operator: slimv1.LabelSelectorOpExists,
		}},
	}
	err = mgr.AddTracingPolicy(ctx, &policy)
	require.Error(t, err)
}

func TestPolicyStates(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	t.Run("LoadError", func(t *testing.T) {
		RegisterPolicyHandlerAtInit("load-fail", &dummyHandler{s: &Sensor{
			Name:  "dummy-sensor",
			Progs: []*program.Program{{Name: "bpf-program-that-does-not-exist"}},
		}})
		t.Cleanup(func() {
			delete(registeredPolicyHandlers, "load-fail")
		})

		policy := v1alpha1.TracingPolicy{}
		mgr, err := StartSensorManager("", nil)
		require.NoError(t, err)
		t.Cleanup(func() {
			if err := mgr.StopSensorManager(ctx); err != nil {
				t.Fatal("failed to stop sensor manager")
			}
		})
		policy.ObjectMeta.Name = "test-policy"
		addError := mgr.AddTracingPolicy(ctx, &policy)
		assert.NotNil(t, addError)

		l, err := mgr.ListTracingPolicies(ctx)
		assert.NoError(t, err)
		assert.Len(t, l.Policies, 1)
		assert.Equal(t, LoadErrorState.ToTetragonState(), l.Policies[0].State)
		assert.Equal(t, addError.Error(), l.Policies[0].Error)
	})

	t.Run("EnabledDisabled", func(t *testing.T) {
		RegisterPolicyHandlerAtInit("dummy", &dummyHandler{s: &Sensor{Name: "dummy-sensor"}})
		t.Cleanup(func() {
			delete(registeredPolicyHandlers, "dummy")
		})

		policy := v1alpha1.TracingPolicy{}
		mgr, err := StartSensorManager("", nil)
		require.NoError(t, err)
		t.Cleanup(func() {
			if err := mgr.StopSensorManager(ctx); err != nil {
				t.Fatal("failed to stop sensor manager")
			}
		})
		policy.ObjectMeta.Name = "test-policy"
		err = mgr.AddTracingPolicy(ctx, &policy)
		assert.NoError(t, err)

		l, err := mgr.ListTracingPolicies(ctx)
		assert.NoError(t, err)
		assert.Len(t, l.Policies, 1)
		assert.Equal(t, EnabledState.ToTetragonState(), l.Policies[0].State)

		err = mgr.DisableTracingPolicy(ctx, policy.ObjectMeta.Name, policy.Namespace)
		assert.NoError(t, err)
		l, err = mgr.ListTracingPolicies(ctx)
		assert.NoError(t, err)
		assert.Len(t, l.Policies, 1)
		assert.Equal(t, DisabledState.ToTetragonState(), l.Policies[0].State)
	})
}

// TestPolicyLoadErrorOverride tests the fact that you can add a TracingPolicy
// with the same name as an existing one if it's in a LoadError state
func TestPolicyLoadErrorOverride(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	RegisterPolicyHandlerAtInit("load-fail", &dummyHandler{s: &Sensor{
		Name:  "dummy-sensor",
		Progs: []*program.Program{{Name: "bpf-program-that-does-not-exist"}},
	}})
	t.Cleanup(func() {
		delete(registeredPolicyHandlers, "load-fail")
	})

	policy := v1alpha1.TracingPolicy{}
	mgr, err := StartSensorManager("", nil)
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := mgr.StopSensorManager(ctx); err != nil {
			t.Fatal("failed to stop sensor manager")
		}
	})
	policy.ObjectMeta.Name = "test-policy"
	addError := mgr.AddTracingPolicy(ctx, &policy)
	assert.NotNil(t, addError)

	l, err := mgr.ListTracingPolicies(ctx)
	assert.NoError(t, err)
	assert.Len(t, l.Policies, 1)
	assert.Equal(t, LoadErrorState.ToTetragonState(), l.Policies[0].State)
	assert.Equal(t, addError.Error(), l.Policies[0].Error)

	// try to override the existing registered LoadError policy
	delete(registeredPolicyHandlers, "load-fail")
	RegisterPolicyHandlerAtInit("dummy", &dummyHandler{s: &Sensor{Name: "dummy-sensor"}})
	t.Cleanup(func() {
		delete(registeredPolicyHandlers, "dummy")
	})
	addError = mgr.AddTracingPolicy(ctx, &policy)
	assert.NoError(t, addError)

	l, err = mgr.ListTracingPolicies(ctx)
	assert.NoError(t, err)
	assert.Len(t, l.Policies, 1)
	assert.Equal(t, EnabledState.ToTetragonState(), l.Policies[0].State)
}

func TestPolicyListingWhileLoadUnload(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	polName := "test-policy"
	testSensor := makeTestDelayedSensor(t)

	mgr, err := StartSensorManager("", nil)
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := mgr.StopSensorManager(ctx); err != nil {
			t.Fatal("failed to stop sensor manager")
		}
	})

	checkPolicy := func(t *testing.T, statuses []*tetragon.TracingPolicyStatus, state tetragon.TracingPolicyState) {
		require.Equal(t, 1, len(statuses))
		pol := statuses[0]
		require.Equal(t, pol.Name, polName)
		require.Equal(t, pol.State, state)
	}

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		// wait until at least one policy shows up, verify that it's in loading state and
		// unblock the loading of the policy
		for {
			l, err := mgr.ListTracingPolicies(ctx)
			require.NoError(t, err)
			if len(l.Policies) > 0 {
				checkPolicy(t, l.Policies, tetragon.TracingPolicyState_TP_STATE_LOADING)
				testSensor.unblock(t)
				break
			}
			time.Sleep(1 * time.Millisecond)
		}
		wg.Done()
	}()

	t.Log("adding policy")
	policy := v1alpha1.TracingPolicy{}
	policy.ObjectMeta.Name = polName
	err = mgr.AddTracingPolicy(ctx, &policy)
	require.NoError(t, err)
	wg.Wait()

	// check that policy is now enabled
	l, err := mgr.ListTracingPolicies(ctx)
	require.NoError(t, err)
	checkPolicy(t, l.Policies, tetragon.TracingPolicyState_TP_STATE_ENABLED)

	wg.Add(1)
	go func() {
		// wait until at least one policy shows up, verify that it's in unloading state and
		// unblock the unloading of the policy
		for {
			l, err := mgr.ListTracingPolicies(ctx)
			require.NoError(t, err)
			require.Equal(t, len(l.Policies), 1)
			if l.Policies[0].State == tetragon.TracingPolicyState_TP_STATE_UNLOADING {
				testSensor.unblock(t)
				break
			}
			time.Sleep(1 * time.Millisecond)
		}
		wg.Done()
	}()

	t.Log("disabling policy")
	err = mgr.DisableTracingPolicy(ctx, polName, "")
	require.NoError(t, err)
	wg.Wait()

	// check that policy is now disabled
	l, err = mgr.ListTracingPolicies(ctx)
	require.NoError(t, err)
	checkPolicy(t, l.Policies, tetragon.TracingPolicyState_TP_STATE_DISABLED)

	wg.Add(1)
	go func() {
		for {
			l, err := mgr.ListTracingPolicies(ctx)
			require.NoError(t, err)
			require.Equal(t, len(l.Policies), 1, "policies:", l.Policies)
			if l.Policies[0].State == tetragon.TracingPolicyState_TP_STATE_LOADING {
				testSensor.unblock(t)
				break
			}
			time.Sleep(1000 * time.Millisecond)
		}
		wg.Done()
	}()

	t.Log("re-enabling policy")
	err = mgr.EnableTracingPolicy(ctx, polName, "")
	require.NoError(t, err)
	wg.Wait()

	// check that policy is now diabled
	l, err = mgr.ListTracingPolicies(ctx)
	require.NoError(t, err)
	checkPolicy(t, l.Policies, tetragon.TracingPolicyState_TP_STATE_ENABLED)

	t.Log("deleting policy")
	err = mgr.DeleteTracingPolicy(ctx, polName, "")
	require.NoError(t, err)
	l, err = mgr.ListTracingPolicies(ctx)
	require.NoError(t, err)
	require.Equal(t, 0, len(l.Policies))
}
