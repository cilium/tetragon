// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/testutils"
)

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

func TestUprobeEventConfigCarriesPolicyID(t *testing.T) {
	spec := &v1alpha1.UProbeSpec{
		Path:    testutils.RepoRootPath("contrib/tester-progs/uprobe-test-1"),
		Symbols: []string{"main"},
	}

	ids, err := addUprobe(spec, nil, &addUprobeIn{policyID: 7}, &uprobeHas{})
	require.NoError(t, err)
	require.NotEmpty(t, ids)

	for _, id := range ids {
		uprobeEntry, err := genericUprobeTableGet(id)
		require.NoError(t, err)
		require.Equal(t, uint32(7), uprobeEntry.loadArgs.config.PolicyID)
	}
}
