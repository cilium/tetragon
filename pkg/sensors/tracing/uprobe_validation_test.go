// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"testing"

	"github.com/stretchr/testify/require"

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

func TestUprobeValidationMultiplePreloadArguments(t *testing.T) {

	// Using multiple preload arguments

	uprobe := testutils.RepoRootPath("contrib/tester-progs/usdt-override")
	crd := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe"
spec:
  uprobes:
  - path: "` + uprobe + `"
    symbols:
    - "test_3"
    data:
    - index: 0
      type: "string"
      source: "pt_regs"
      resolve: "rdi"
    - index: 1
      type: "string"
      source: "pt_regs"
      resolve: "rsi"
`

	err := checkCrd(t, crd)
	require.Error(t, err)
}
