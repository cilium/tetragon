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

func TestUprobeValidationTargets(t *testing.T) {
	tests := []struct {
		name    string
		spec    v1alpha1.UProbeSpec
		wantErr string
	}{
		{
			name:    "missing target",
			spec:    v1alpha1.UProbeSpec{},
			wantErr: "exactly one of Symbols, Offsets or Addrs",
		},
		{
			name: "symbols and offsets",
			spec: v1alpha1.UProbeSpec{
				Symbols: []string{"main"},
				Offsets: []uint64{1},
			},
			wantErr: "only one of Symbols, Offsets or Addrs",
		},
		{
			name: "offsets and addrs",
			spec: v1alpha1.UProbeSpec{
				Offsets: []uint64{1},
				Addrs:   []uint64{2},
			},
			wantErr: "only one of Symbols, Offsets or Addrs",
		},
		{
			name: "addrs refctr mismatch",
			spec: v1alpha1.UProbeSpec{
				Addrs:         []uint64{1, 2},
				RefCtrOffsets: []uint64{3},
			},
			wantErr: "RefCtrOffsets(1) has different dimension than Addrs(2)",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := addUprobe(&test.spec, nil, &addUprobeIn{}, &uprobeHas{})
			require.ErrorContains(t, err, test.wantErr)
		})
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
