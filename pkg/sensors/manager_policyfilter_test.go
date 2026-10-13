// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !nok8s

package sensors

import (
	"context"
	"testing"
	"time"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/labels"
	"github.com/cilium/tetragon/pkg/manager/events"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/podhelpers"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors/program"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	slimv1 "github.com/cilium/tetragon/pkg/k8s/slim/k8s/apis/meta/v1"
)

// mockPolicyFilterState is a policyfilter.State implementation that records
// policyfilter ID allocations and releases, so tests can assert that no IDs
// leak across policy add/delete cycles.
type mockPolicyFilterState struct {
	added   []policyfilter.PolicyID
	deleted []policyfilter.PolicyID
}

func (m *mockPolicyFilterState) AddPolicy(polID policyfilter.PolicyID, _ string, _ *slimv1.LabelSelector,
	_ *slimv1.LabelSelector, _ *slimv1.LabelSelector) error {
	m.added = append(m.added, polID)
	return nil
}

func (m *mockPolicyFilterState) DelPolicy(polID policyfilter.PolicyID) error {
	m.deleted = append(m.deleted, polID)
	return nil
}

func (m *mockPolicyFilterState) numAdded() int {
	return len(m.added)
}

// liveIDs returns the IDs that were allocated but never released.
func (m *mockPolicyFilterState) liveIDs() []policyfilter.PolicyID {
	deleted := make(map[policyfilter.PolicyID]int)
	for _, id := range m.deleted {
		deleted[id]++
	}
	var live []policyfilter.PolicyID
	for _, id := range m.added {
		if deleted[id] > 0 {
			deleted[id]--
			continue
		}
		live = append(live, id)
	}
	return live
}

func (m *mockPolicyFilterState) AddPodContainer(_ policyfilter.PodID, _ string, _ labels.Labels,
	_ string, _ policyfilter.CgroupID, _ podhelpers.ContainerInfo) error {
	return nil
}

func (m *mockPolicyFilterState) UpdatePod(_ policyfilter.PodID, _ string, _ labels.Labels,
	_ []string, _ []podhelpers.ContainerInfo) error {
	return nil
}

func (m *mockPolicyFilterState) DelPodContainer(_ policyfilter.PodID, _ string) error {
	return nil
}

func (m *mockPolicyFilterState) DelPod(_ policyfilter.PodID) error {
	return nil
}

func (m *mockPolicyFilterState) RegisterPodHandlers(_ events.PodEventSource) error {
	return nil
}

func (m *mockPolicyFilterState) Close() error {
	return nil
}

// TestPolicyLoadErrorOverrideNoPolicyFilterLeak is a regression test for
// https://github.com/cilium/tetragon/issues/5707: re-adding a policy over a
// LoadErrorState entry must not leak policyfilter IDs.
func TestPolicyLoadErrorOverrideNoPolicyFilterLeak(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	oldEnableK8s := option.Config.EnableK8s
	option.Config.EnableK8s = true
	t.Cleanup(func() {
		option.Config.EnableK8s = oldEnableK8s
	})

	RegisterPolicyHandlerAtInit("load-fail", &dummyHandler{s: &Sensor{
		Name:  "dummy-sensor",
		Progs: []*program.Program{{Name: "bpf-program-that-does-not-exist"}},
	}})
	t.Cleanup(func() {
		delete(registeredPolicyHandlers, "load-fail")
	})

	pfState := &mockPolicyFilterState{}
	mgr, err := StartSensorManagerWithPF("", pfState)
	require.NoError(t, err)

	// NB: the podSelector is what makes updatePolicyFilter register a
	// policyfilter ID; without any selectors no filter is ever registered
	// and the leak cannot be observed.
	policy := v1alpha1.TracingPolicy{
		Name: "test-policy",
		Spec: v1alpha1.TracingPolicySpec{
			PodSelector: &slimv1.LabelSelector{
				MatchLabels: map[string]string{"app": "leak-repro"},
			},
		},
	}
	// the first add fails to load, but the registered filter ID must be
	// rolled back instead of being left behind
	require.Error(t, mgr.AddTracingPolicy(ctx, &policy))
	l, err := mgr.ListTracingPolicies(ctx, policy.TpDomain())
	require.NoError(t, err)
	require.Len(t, l.Policies, 1)
	assert.Equal(t, LoadErrorState.ToTetragonState(), l.Policies[0].State)
	assert.Equal(t, 1, pfState.numAdded())
	assert.Empty(t, pfState.liveIDs(), "policyfilter ID leaked by failed add")

	// re-adding over the LoadErrorState entry replaces it; the new
	// entry's filter ID must be released as well when the load fails again
	require.Error(t, mgr.AddTracingPolicy(ctx, &policy))
	l, err = mgr.ListTracingPolicies(ctx, policy.TpDomain())
	require.NoError(t, err)
	require.Len(t, l.Policies, 1)
	assert.Equal(t, LoadErrorState.ToTetragonState(), l.Policies[0].State)
	assert.Equal(t, 2, pfState.numAdded())
	assert.Empty(t, pfState.liveIDs(), "policyfilter ID leaked by re-add over LoadErrorState entry")

	// deleting the failed policy must leave no filter IDs behind
	require.NoError(t, mgr.DeleteTracingPolicy(ctx, policy.Name, "", policy.TpDomain()))
	assert.Empty(t, pfState.liveIDs(), "policyfilter ID leaked after delete")
}

// TestPolicyEnableErrorNoPolicyFilterLeak is a regression test for the
// enable counterpart of #5707: a policy that was added in a disabled state
// holds a policyfilter ID, and if enabling it fails to load, the ID must be
// released when the collection lands in LoadErrorState.
func TestPolicyEnableErrorNoPolicyFilterLeak(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	oldEnableK8s := option.Config.EnableK8s
	option.Config.EnableK8s = true
	t.Cleanup(func() {
		option.Config.EnableK8s = oldEnableK8s
	})

	RegisterPolicyHandlerAtInit("load-fail", &dummyHandler{s: &Sensor{
		Name:  "dummy-sensor",
		Progs: []*program.Program{{Name: "bpf-program-that-does-not-exist"}},
	}})
	t.Cleanup(func() {
		delete(registeredPolicyHandlers, "load-fail")
	})

	pfState := &mockPolicyFilterState{}
	mgr, err := StartSensorManagerWithPF("", pfState)
	require.NoError(t, err)

	// NB: as in TestPolicyLoadErrorOverrideNoPolicyFilterLeak, the
	// podSelector is what makes updatePolicyFilter register a
	// policyfilter ID.
	policy := v1alpha1.TracingPolicy{
		Name: "test-policy",
		Spec: v1alpha1.TracingPolicySpec{
			PodSelector: &slimv1.LabelSelector{
				MatchLabels: map[string]string{"app": "leak-repro"},
			},
		},
	}
	// adding the policy in a disabled state does not load it, so it
	// succeeds and its filter ID stays registered
	require.NoError(t, mgr.AddTracingPolicyWithState(ctx, &policy, DisabledState))
	l, err := mgr.ListTracingPolicies(ctx, policy.TpDomain())
	require.NoError(t, err)
	require.Len(t, l.Policies, 1)
	assert.Equal(t, DisabledState.ToTetragonState(), l.Policies[0].State)
	assert.Equal(t, 1, pfState.numAdded())
	assert.Len(t, pfState.liveIDs(), 1, "disabled policy should hold its policyfilter ID")

	// enabling the policy fails to load: the collection lands in
	// LoadErrorState and its filter ID must be released
	require.Error(t, mgr.EnableTracingPolicy(ctx, policy.Name, "", policy.TpDomain()))
	l, err = mgr.ListTracingPolicies(ctx, policy.TpDomain())
	require.NoError(t, err)
	require.Len(t, l.Policies, 1)
	assert.Equal(t, LoadErrorState.ToTetragonState(), l.Policies[0].State)
	assert.Empty(t, pfState.liveIDs(), "policyfilter ID leaked by failed enable")

	// re-adding over the LoadErrorState entry replaces it; the new
	// entry's filter ID must be released as well when the load fails again
	require.Error(t, mgr.AddTracingPolicy(ctx, &policy))
	assert.Equal(t, 2, pfState.numAdded())
	assert.Empty(t, pfState.liveIDs(), "policyfilter ID leaked by re-add over LoadErrorState entry")

	// deleting the failed policy must leave no filter IDs behind
	require.NoError(t, mgr.DeleteTracingPolicy(ctx, policy.Name, "", policy.TpDomain()))
	assert.Empty(t, pfState.liveIDs(), "policyfilter ID leaked after delete")
}
