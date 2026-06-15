// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"
)

const clusterScopedPolicy = `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: test-policy
spec:
  kprobes:
  - call: sys_write
    syscall: true
`

func TestScopePolicy_NotScoped(t *testing.T) {
	// when the conf is not pod-scoped (the local case), the policy is returned
	// unchanged.
	got, err := ScopePolicy(&Conf{}, Policy(clusterScopedPolicy))
	require.NoError(t, err)
	assert.Equal(t, Policy(clusterScopedPolicy), got)
}

func TestScopePolicy_Namespaced(t *testing.T) {
	conf := &Conf{
		Namespace:         "test-ns",
		PodSelectorLabels: map[string]string{"app": "policytest", "run": "abc123"},
	}

	got, err := ScopePolicy(conf, Policy(clusterScopedPolicy))
	require.NoError(t, err)

	var obj map[string]any
	require.NoError(t, yaml.Unmarshal([]byte(got), &obj))

	// kind is rewritten to the namespaced CRD
	assert.Equal(t, "TracingPolicyNamespaced", obj["kind"])

	// namespace is set on metadata, name preserved
	meta := obj["metadata"].(map[string]any)
	assert.Equal(t, "test-ns", meta["namespace"])
	assert.Equal(t, "test-policy", meta["name"])

	// podSelector matchLabels injected into the spec
	spec := obj["spec"].(map[string]any)
	podSelector := spec["podSelector"].(map[string]any)
	assert.Equal(t, map[string]any{"app": "policytest", "run": "abc123"}, podSelector["matchLabels"])

	// original spec content (kprobes) is preserved
	assert.Contains(t, spec, "kprobes")
}
