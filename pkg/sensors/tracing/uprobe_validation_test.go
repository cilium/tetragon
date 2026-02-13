// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"testing"

	"github.com/stretchr/testify/require"

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
