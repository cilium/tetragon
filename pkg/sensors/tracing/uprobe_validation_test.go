// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	slimv1 "github.com/cilium/tetragon/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/tetragon/pkg/testutils"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

func TestUprobeResolvePathInContainerField(t *testing.T) {
	withField := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe"
spec:
  podSelector:
    matchLabels:
      app: sshd
  uprobes:
  - path: "/usr/lib64/libpam.so.0.85.1"
    symbols:
    - "pam_authenticate"
    resolvePathInContainer: true
`
	tp, err := tracingpolicy.FromYAML(withField)
	require.NoError(t, err)
	require.Len(t, tp.TpSpec().UProbes, 1)
	require.True(t, tp.TpSpec().UProbes[0].ResolvePathInContainer,
		"resolvePathInContainer: true should round-trip through CRD parsing")

	withoutField := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe"
spec:
  uprobes:
  - path: "/bin/bash"
    symbols:
    - "main"
`
	tp, err = tracingpolicy.FromYAML(withoutField)
	require.NoError(t, err)
	require.Len(t, tp.TpSpec().UProbes, 1)
	require.False(t, tp.TpSpec().UProbes[0].ResolvePathInContainer,
		"resolvePathInContainer should default to false when omitted")
}

func TestUprobeValidationResolvePathInContainerRequiresPodSelector(t *testing.T) {
	uprobe := testutils.RepoRootPath("contrib/tester-progs/regs-override")

	// resolvePathInContainer without a podSelector must be rejected. The CRD (CEL)
	// catches this at parse time, so assert on FromYAML directly.
	noSelector := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe"
spec:
  uprobes:
  - path: "` + uprobe + `"
    symbols:
    - "test_1"
    resolvePathInContainer: true
`
	_, err := tracingpolicy.FromYAML(noSelector)
	require.Error(t, err)
	require.ErrorContains(t, err, "podSelector")

	// With a podSelector, the policy must pass the podSelector gate. The rest
	// of the pipeline may still fail in this environment (e.g. the tester
	// binary is not built, or per-container ELF resolution is not yet wired
	// up), but it must not be rejected for the missing-podSelector reason.
	withSelector := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe"
spec:
  podSelector:
    matchLabels:
      app: sshd
  uprobes:
  - path: "` + uprobe + `"
    symbols:
    - "test_1"
    resolvePathInContainer: true
`
	err = checkCrd(t, withSelector)
	if err != nil {
		require.NotContains(t, err.Error(), "podSelector",
			"a policy with a podSelector must not be rejected for the missing-podSelector reason")
	}
}

// The reconciler matches pods, not containers: a containerSelector would
// still resolve and attach in excluded containers, so it must be rejected
// rather than silently attaching more widely than the policy asks for.
func TestUprobeValidationResolvePathInContainerRejectsContainerSelector(t *testing.T) {
	crd := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe"
spec:
  podSelector:
    matchLabels:
      app: sshd
  containerSelector:
    matchExpressions:
    - key: name
      operator: In
      values:
      - sshd
  uprobes:
  - path: "/only/exists/in/the/container"
    symbols:
    - "test_1"
    resolvePathInContainer: true
`

	// The CRD (CEL) catches this at parse time, so assert on FromYAML directly.
	_, err := tracingpolicy.FromYAML(crd)
	require.Error(t, err)
	require.ErrorContains(t, err, "containerSelector")

	// The agent-side check must reject it too: policies also reach the sensor
	// without passing through API-server validation.
	spec := &v1alpha1.TracingPolicySpec{
		PodSelector:       &slimv1.LabelSelector{},
		ContainerSelector: &slimv1.LabelSelector{},
		UProbes: []v1alpha1.UProbeSpec{{
			Path:                   "/only/exists/in/the/container",
			Symbols:                []string{"test_1"},
			ResolvePathInContainer: true,
		}},
	}
	require.ErrorContains(t, preValidateUprobes(spec), "containerSelector")
}

func TestUprobeEventConfigCarriesPolicyID(t *testing.T) {
	var state uprobeConfigState
	err := initUprobeArgs(&v1alpha1.UProbeSpec{}, &uprobeHas{}, &addUprobeIn{policyID: 7}, &state)
	require.NoError(t, err)
	require.Equal(t, uint32(7), state.eventConfig.PolicyID)
}
