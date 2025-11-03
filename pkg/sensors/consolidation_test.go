//go:build !windows

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package sensors

import (
	"testing"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockTracingPolicy implements the TracingPolicy interface for testing
type mockTracingPolicy struct {
	name string
	spec *v1alpha1.TracingPolicySpec
}

func (m *mockTracingPolicy) TpName() string {
	return m.name
}

func (m *mockTracingPolicy) TpSpec() *v1alpha1.TracingPolicySpec {
	return m.spec
}

func (m *mockTracingPolicy) TpInfo() string {
	return "mock policy: " + m.name
}

func TestFunctionAttachmentManager_AddPolicy(t *testing.T) {
	fam := NewFunctionAttachmentManager()

	// Create a mock policy with kprobes
	policy1 := &mockTracingPolicy{
		name: "policy1",
		spec: &v1alpha1.TracingPolicySpec{
			KProbes: []v1alpha1.KProbeSpec{
				{
					Call: "sys_open",
				},
				{
					Call: "sys_read",
				},
			},
		},
	}

	err := fam.AddPolicy(policy1, policyfilter.PolicyID(1))
	require.NoError(t, err)

	// Check that the policy was added
	stats := fam.GetStats()
	assert.Equal(t, 2, stats.TotalFunctions) // sys_open and sys_read
	assert.Equal(t, 2, stats.TotalPolicies)  // 2 kprobe specs
	assert.Equal(t, 0, stats.ConsolidationCandidates) // No candidates yet (need multiple policies per function)
}

func TestFunctionAttachmentManager_ConsolidationCandidates(t *testing.T) {
	fam := NewFunctionAttachmentManager()

	// Create two policies that hook the same function
	policy1 := &mockTracingPolicy{
		name: "policy1",
		spec: &v1alpha1.TracingPolicySpec{
			KProbes: []v1alpha1.KProbeSpec{
				{
					Call: "sys_open",
				},
			},
		},
	}

	policy2 := &mockTracingPolicy{
		name: "policy2", 
		spec: &v1alpha1.TracingPolicySpec{
			KProbes: []v1alpha1.KProbeSpec{
				{
					Call: "sys_open", // Same function as policy1
				},
			},
		},
	}

	err := fam.AddPolicy(policy1, policyfilter.PolicyID(1))
	require.NoError(t, err)

	err = fam.AddPolicy(policy2, policyfilter.PolicyID(2))
	require.NoError(t, err)

	// Check consolidation candidates
	candidates := fam.GetConsolidationCandidates()
	assert.Len(t, candidates, 1)
	assert.Contains(t, candidates, "sys_open")
	assert.Len(t, candidates["sys_open"], 2) // Two policies hooking sys_open

	// Check that consolidation is recommended
	assert.True(t, fam.ShouldConsolidate("sys_open"))
	assert.False(t, fam.ShouldConsolidate("sys_read")) // Only one policy hooks this

	stats := fam.GetStats()
	assert.Equal(t, 1, stats.TotalFunctions)
	assert.Equal(t, 2, stats.TotalPolicies)
	assert.Equal(t, 1, stats.ConsolidationCandidates)
}

func TestFunctionAttachmentManager_IncompatiblePolicies(t *testing.T) {
	fam := NewFunctionAttachmentManager()

	// Create two policies with different syscall flags (incompatible)
	policy1 := &mockTracingPolicy{
		name: "policy1",
		spec: &v1alpha1.TracingPolicySpec{
			KProbes: []v1alpha1.KProbeSpec{
				{
					Call:    "sys_open",
					Syscall: true,
				},
			},
		},
	}

	policy2 := &mockTracingPolicy{
		name: "policy2",
		spec: &v1alpha1.TracingPolicySpec{
			KProbes: []v1alpha1.KProbeSpec{
				{
					Call:    "sys_open",
					Syscall: false, // Different syscall flag
				},
			},
		},
	}

	err := fam.AddPolicy(policy1, policyfilter.PolicyID(1))
	require.NoError(t, err)

	err = fam.AddPolicy(policy2, policyfilter.PolicyID(2))
	require.NoError(t, err)

	// These policies should not be consolidation candidates due to incompatibility
	candidates := fam.GetConsolidationCandidates()
	assert.Len(t, candidates, 0) // No compatible candidates

	assert.False(t, fam.ShouldConsolidate("sys_open"))
}

func TestFunctionAttachmentManager_RemovePolicy(t *testing.T) {
	fam := NewFunctionAttachmentManager()

	policy1 := &mockTracingPolicy{
		name: "policy1",
		spec: &v1alpha1.TracingPolicySpec{
			KProbes: []v1alpha1.KProbeSpec{
				{
					Call: "sys_open",
				},
			},
		},
	}

	policy2 := &mockTracingPolicy{
		name: "policy2",
		spec: &v1alpha1.TracingPolicySpec{
			KProbes: []v1alpha1.KProbeSpec{
				{
					Call: "sys_open",
				},
			},
		},
	}

	// Add both policies
	err := fam.AddPolicy(policy1, policyfilter.PolicyID(1))
	require.NoError(t, err)

	err = fam.AddPolicy(policy2, policyfilter.PolicyID(2))
	require.NoError(t, err)

	// Should have consolidation candidate
	assert.True(t, fam.ShouldConsolidate("sys_open"))

	// Remove one policy
	err = fam.RemovePolicy("policy1")
	require.NoError(t, err)

	// Should no longer have consolidation candidate
	assert.False(t, fam.ShouldConsolidate("sys_open"))

	stats := fam.GetStats()
	assert.Equal(t, 1, stats.TotalFunctions)
	assert.Equal(t, 1, stats.TotalPolicies)
	assert.Equal(t, 0, stats.ConsolidationCandidates)
}

func TestFunctionAttachmentManager_CreateConsolidatedProgram(t *testing.T) {
	fam := NewFunctionAttachmentManager()

	// Create mock policies
	policies := []PolicyInfo{
		{
			Name:     "policy1",
			PolicyID: policyfilter.PolicyID(1),
			KprobeSpecs: []KprobeSpec{
				{
					FunctionName: "sys_open",
					Syscall:      false,
					RetProbe:     false,
					Instance:     0,
				},
			},
		},
		{
			Name:     "policy2",
			PolicyID: policyfilter.PolicyID(2),
			KprobeSpecs: []KprobeSpec{
				{
					FunctionName: "sys_open",
					Syscall:      false,
					RetProbe:     false,
					Instance:     0,
				},
			},
		},
	}

	consolidated, err := fam.CreateConsolidatedProgram("sys_open", policies)
	require.NoError(t, err)
	require.NotNil(t, consolidated)

	assert.Equal(t, "sys_open", consolidated.FunctionName)
	assert.Len(t, consolidated.Policies, 2)
	assert.Equal(t, "policy1", consolidated.Policies[0].Name)
	assert.Equal(t, "policy2", consolidated.Policies[1].Name)

	// Test that getting the same consolidated program returns the existing one
	consolidated2, err := fam.CreateConsolidatedProgram("sys_open", policies)
	require.NoError(t, err)
	assert.Equal(t, consolidated, consolidated2) // Should be the same instance
}

func TestConsolidationStats_String(t *testing.T) {
	stats := ConsolidationStats{
		TotalFunctions:           5,
		TotalPolicies:           10,
		ConsolidatedFunctions:   2,
		ConsolidationCandidates: 3,
	}

	expected := "Functions: 5, Policies: 10, Consolidated: 2, Candidates: 3"
	assert.Equal(t, expected, stats.String())
}
