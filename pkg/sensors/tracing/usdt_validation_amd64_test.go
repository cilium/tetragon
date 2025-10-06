// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"testing"

	"github.com/stretchr/testify/require"

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
