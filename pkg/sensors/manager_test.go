// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package sensors

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/tracingpolicy"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	slimv1 "github.com/cilium/tetragon/pkg/k8s/slim/k8s/apis/meta/v1"
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
	mgr, err := StartSensorManager("")
	require.NoError(t, err)
	policy.Name = "test-policy"
	err = mgr.AddTracingPolicy(ctx, &policy)
	require.NoError(t, err)
	l, err := mgr.ListSensors(ctx)
	require.NoError(t, err)
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
	mgr, err := StartSensorManager("")
	require.NoError(t, err)
	policy.Name = "test-policy"
	err = mgr.AddTracingPolicy(ctx, &policy)
	require.NoError(t, err)
	l, err := mgr.ListSensors(ctx)
	require.NoError(t, err)
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
	mgr, err := StartSensorManager("")
	require.NoError(t, err)
	policy.Name = "test-policy"
	err = mgr.AddTracingPolicy(ctx, &policy)
	require.Error(t, err)
	t.Logf("got error (as expected): %s", err)
	l, err := mgr.ListSensors(ctx)
	require.NoError(t, err)
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
	mgr, err := StartSensorManager("")
	require.NoError(t, err)
	policy.Name = "test-policy"
	addError := mgr.AddTracingPolicy(ctx, &policy)
	require.Error(t, addError)
	t.Logf("got error (as expected): %s", addError)

	l, err := mgr.ListTracingPolicies(ctx)
	require.NoError(t, err)
	assert.Len(t, l.Policies, 1)
	assert.Equal(t, LoadErrorState.ToTetragonState(), l.Policies[0].State)
	assert.Equal(t, addError.Error(), l.Policies[0].Error)
}

func TestPolicyFilterDisabled(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	mgr, err := StartSensorManagerWithPF("", policyfilter.DisabledState())
	require.NoError(t, err)

	policy := v1alpha1.TracingPolicy{}

	// normal policy should succeed
	policyName := "test-policy"
	policyNamespace := ""
	policy.Name = policyName
	err = mgr.AddTracingPolicy(ctx, &policy)
	require.NoError(t, err, "Add tracing policy failed with error: %v", err)
	err = mgr.DeleteTracingPolicy(ctx, policyName, policyNamespace)
	require.NoError(t, err)
	err = mgr.AddTracingPolicy(ctx, &policy)
	require.NoError(t, err)
	err = mgr.DeleteTracingPolicy(ctx, policyName, policyNamespace)
	require.NoError(t, err)

	// namespaced policy with disabled state should fail
	namespacedPolicy := v1alpha1.TracingPolicyNamespaced{}
	policy.Name = policyName
	namespacedPolicy.Name = policyName
	namespacedPolicy.Namespace = "namespace"
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
		mgr, err := StartSensorManager("")
		require.NoError(t, err)
		policy.Name = "test-policy"
		addError := mgr.AddTracingPolicy(ctx, &policy)
		require.Error(t, addError)

		l, err := mgr.ListTracingPolicies(ctx)
		require.NoError(t, err)
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
		mgr, err := StartSensorManager("")
		require.NoError(t, err)
		policy.Name = "test-policy"
		err = mgr.AddTracingPolicy(ctx, &policy)
		require.NoError(t, err)

		l, err := mgr.ListTracingPolicies(ctx)
		require.NoError(t, err)
		assert.Len(t, l.Policies, 1)
		assert.Equal(t, EnabledState.ToTetragonState(), l.Policies[0].State)

		err = mgr.DisableTracingPolicy(ctx, policy.Name, policy.Namespace)
		require.NoError(t, err)
		l, err = mgr.ListTracingPolicies(ctx)
		require.NoError(t, err)
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
	mgr, err := StartSensorManager("")
	require.NoError(t, err)
	policy.Name = "test-policy"
	addError := mgr.AddTracingPolicy(ctx, &policy)
	require.Error(t, addError)

	l, err := mgr.ListTracingPolicies(ctx)
	require.NoError(t, err)
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
	require.NoError(t, addError)

	l, err = mgr.ListTracingPolicies(ctx)
	require.NoError(t, err)
	assert.Len(t, l.Policies, 1)
	assert.Equal(t, EnabledState.ToTetragonState(), l.Policies[0].State)
}

func TestPolicyListCollections(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	RegisterPolicyHandlerAtInit("dummy", &dummyHandler{s: &Sensor{Name: "dummy-sensor"}})
	t.Cleanup(func() {
		delete(registeredPolicyHandlers, "dummy")
	})

	kprobes := []v1alpha1.KProbeSpec{
		{
			Call:    "dummy",
			Message: "dummy",
		},
	}
	policy := v1alpha1.TracingPolicy{Spec: v1alpha1.TracingPolicySpec{KProbes: kprobes}}
	mgr, err := StartSensorManager("")
	require.NoError(t, err)
	policy.Name = "test-policy"
	err = mgr.AddTracingPolicy(ctx, &policy)
	require.NoError(t, err)

	l, err := mgr.ListTracingPolicies(ctx)
	require.NoError(t, err)
	assert.Len(t, l.Policies, 1)
	assert.Equal(t, EnabledState.ToTetragonState(), l.Policies[0].State)

	collections := mgr.ListCollections(ctx, true)
	assert.Len(t, collections, 1)
	assert.Equal(t, kprobes, collections[0].TracingpolicySpec.KProbes)
}

func TestPolicyListingWhileLoadUnload(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	polName := "test-policy"
	testSensor := makeTestDelayedSensor(t)

	mgr, err := StartSensorManager("")
	require.NoError(t, err)

	wrongPolicyErr := errors.New("wrong policy state")

	checkPolicy := func(statuses []*tetragon.TracingPolicyStatus, state tetragon.TracingPolicyState) error {
		if len(statuses) != 1 {
			return fmt.Errorf("expected 1 policy, got %d", len(statuses))
		}
		pol := statuses[0]
		if pol.Name != polName {
			return fmt.Errorf("expected policy name %s, got %s", polName, pol.Name)
		}
		if pol.State != state {
			return fmt.Errorf("%w: expected %v, got %v", wrongPolicyErr, state, pol.State)
		}
		return nil
	}

	verifyState := func(errCh chan error, state tetragon.TracingPolicyState) {
		// wait until at least one policy shows up, verify that it's in loading/unloading state and
		// unblock the loading/unloading of the policy
		for {
			l, err := mgr.ListTracingPolicies(ctx)
			if err != nil {
				errCh <- fmt.Errorf("ListTracingPolicies error: %w", err)
				return
			}
			if len(l.Policies) > 0 {
				err := checkPolicy(l.Policies, state)
				if err != nil && !errors.Is(err, wrongPolicyErr) {
					errCh <- err
					return
				}
				testSensor.unblock(t)
				errCh <- nil
				return
			}
			time.Sleep(1 * time.Millisecond)
		}
	}

	errCh := make(chan error, 1)
	go verifyState(errCh, tetragon.TracingPolicyState_TP_STATE_LOADING)

	t.Log("adding policy")
	policy := v1alpha1.TracingPolicy{}
	policy.Name = polName
	mgrErrCh := make(chan error, 1)
	go func() {
		mgrErrCh <- mgr.AddTracingPolicy(ctx, &policy)
	}()

	for range 2 {
		select {
		case err := <-mgrErrCh:
			require.NoError(t, err)
		case err := <-errCh:
			require.NoError(t, err)
		}
	}

	// check that policy is now enabled
	l, err := mgr.ListTracingPolicies(ctx)
	require.NoError(t, err)
	err = checkPolicy(l.Policies, tetragon.TracingPolicyState_TP_STATE_ENABLED)
	require.NoError(t, err)

	errCh = make(chan error, 1)
	go verifyState(errCh, tetragon.TracingPolicyState_TP_STATE_UNLOADING)

	t.Log("disabling policy")
	mgrErrCh = make(chan error, 1)
	go func() {
		mgrErrCh <- mgr.DisableTracingPolicy(ctx, polName, "")
	}()

	for range 2 {
		select {
		case err := <-mgrErrCh:
			require.NoError(t, err)
		case err := <-errCh:
			require.NoError(t, err)
		}
	}

	// check that policy is now disabled
	l, err = mgr.ListTracingPolicies(ctx)
	require.NoError(t, err)
	err = checkPolicy(l.Policies, tetragon.TracingPolicyState_TP_STATE_DISABLED)
	require.NoError(t, err)

	errCh = make(chan error, 1)
	go verifyState(errCh, tetragon.TracingPolicyState_TP_STATE_LOADING)

	t.Log("re-enabling policy")
	mgrErrCh = make(chan error, 1)
	go func() {
		mgrErrCh <- mgr.EnableTracingPolicy(ctx, polName, "")
	}()

	for range 2 {
		select {
		case err := <-mgrErrCh:
			require.NoError(t, err)
		case err := <-errCh:
			require.NoError(t, err)
		}
	}

	// check that policy is now diabled
	l, err = mgr.ListTracingPolicies(ctx)
	require.NoError(t, err)
	err = checkPolicy(l.Policies, tetragon.TracingPolicyState_TP_STATE_ENABLED)
	require.NoError(t, err)

	t.Log("deleting policy")
	err = mgr.DeleteTracingPolicy(ctx, polName, "")
	require.NoError(t, err)
	l, err = mgr.ListTracingPolicies(ctx)
	require.NoError(t, err)
	require.Empty(t, l.Policies)
}

func TestPolicyKernelMemoryBytes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	RegisterPolicyHandlerAtInit("loaded-map", &dummyHandler{s: &Sensor{Name: "dummy-sensor",
		Progs: []*program.Program{{
			Name:           "bpf-program-that-does-not-exist",
			LoadedMapsInfo: map[int]bpf.ExtendedMapInfo{0: {Memlock: 110}, 1: {Memlock: 120}},
		}, {
			Name:           "bpf-program-that-does-not-exist-2",
			LoadedMapsInfo: map[int]bpf.ExtendedMapInfo{2: {Memlock: 130}, 3: {Memlock: 140}},
		}, {
			Name:           "bpf-program-that-does-not-exist-3",
			LoadedMapsInfo: map[int]bpf.ExtendedMapInfo{2: {Memlock: 130}}, // this will overwrite map ID 2
		}},
	}})
	t.Cleanup(func() {
		delete(registeredPolicyHandlers, "loaded-map")
	})

	policy := v1alpha1.TracingPolicy{}
	mgr, err := StartSensorManager("")
	require.NoError(t, err)
	policy.Name = "test-policy"
	addError := mgr.AddTracingPolicy(ctx, &policy)
	// this will fail to load because the programs do not exist
	require.Error(t, addError)

	l, err := mgr.ListTracingPolicies(ctx)
	require.NoError(t, err)
	require.Len(t, l.Policies, 1)
	assert.Equal(t, uint64(500), l.Policies[0].KernelMemoryBytes)
}
