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

func TestUsdtValidationSetWrongReturnSize1B(t *testing.T) {

	// Using 1 bytes return argument with usdt set action

	usdt := testutils.RepoRootPath("contrib/tester-progs/usdt-override")
	crd := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "usdts"
spec:
  usdts:
  - path: "` + usdt + `"
    provider: "tetragon"
    name: "test_1B"
    args:
    - index: 0
      type: "int32"
    - index: 1
      type: "int32"
    - index: 2
      type: "int32"
    selectors:
    - matchActions:
      - action: Set
        argIndex: 0
        argValue: 240
`

	err := checkCrd(t, crd)
	require.Error(t, err)
}

func TestUsdtValidationSetWrongReturnSize8B(t *testing.T) {

	// Using 8 bytes return argument with usdt set action

	usdt := testutils.RepoRootPath("contrib/tester-progs/usdt-override")
	crd := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "usdts"
spec:
  usdts:
  - path: "` + usdt + `"
    provider: "tetragon"
    name: "test_8B"
    args:
    - index: 0
      type: "int32"
    - index: 1
      type: "int32"
    - index: 2
      type: "int32"
    selectors:
    - matchActions:
      - action: Set
        argIndex: 0
        argValue: 240
`

	err := checkCrd(t, crd)
	require.Error(t, err)
}

func TestUsdtEventConfigCarriesPolicyID(t *testing.T) {
	spec := &v1alpha1.UsdtSpec{
		Path:     testutils.RepoRootPath("contrib/tester-progs/usdt"),
		Provider: "test",
		Name:     "usdt0",
	}

	ids, err := addUsdt(spec, &addUsdtIn{policyID: 7}, nil, &usdtHas{})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, cleanupUsdtEntries(ids)) })
	require.NotEmpty(t, ids)

	for _, id := range ids {
		usdtEntry, err := genericUsdtTableGet(id)
		require.NoError(t, err)
		require.Equal(t, uint32(7), usdtEntry.config.PolicyID)
	}
}
