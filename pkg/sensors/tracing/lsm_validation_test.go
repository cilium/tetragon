// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

func TestLsmValidationBogusHook(t *testing.T) {
	if !bpf.HasLSMPrograms() || !config.EnableLargeProgs() {
		t.Skip("LSM programs not supported on this kernel")
	}

	crd := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "lsm-bogus-hook"
spec:
  lsmhooks:
  - hook: "bogus_nonexistent_hook_xyz"
`

	err := checkCrd(t, crd)
	require.Error(t, err)
}

func TestLsmValidationEmptyHook(t *testing.T) {
	if !bpf.HasLSMPrograms() || !config.EnableLargeProgs() {
		t.Skip("LSM programs not supported on this kernel")
	}

	crd := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "lsm-empty-hook"
spec:
  lsmhooks:
  - hook: ""
`

	err := checkCrd(t, crd)
	require.Error(t, err)
}

func TestLsmValidationInvalidSelector(t *testing.T) {
	if !bpf.HasLSMPrograms() || !config.EnableLargeProgs() {
		t.Skip("LSM programs not supported on this kernel")
	}

	crd := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "lsm-bad-selector"
spec:
  lsmhooks:
  - hook: "file_open"
    selectors:
    - matchReturnArgs:
      - index: 0
        operator: "Equal"
        values:
        - "0"
`

	err := checkCrd(t, crd)
	require.Error(t, err)
}

func TestLsmValidationArgIndexOutOfBounds(t *testing.T) {
	if !bpf.HasLSMPrograms() || !config.EnableLargeProgs() {
		t.Skip("LSM programs not supported on this kernel")
	}

	crd := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "lsm-arg-oob"
spec:
  lsmhooks:
  - hook: "file_open"
    args:
    - index: 5
      type: "int"
`

	err := checkCrd(t, crd)
	require.Error(t, err)
}

func TestLsmValidationInvalidArgType(t *testing.T) {
	if !bpf.HasLSMPrograms() || !config.EnableLargeProgs() {
		t.Skip("LSM programs not supported on this kernel")
	}

	crd := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "lsm-bad-argtype"
spec:
  lsmhooks:
  - hook: "file_open"
    args:
    - index: 0
      type: "bogus_type_xyz"
`

	_, err := tracingpolicy.FromYAML(crd)
	require.Error(t, err)
}

func TestLsmValidationValidPolicy(t *testing.T) {
	if !bpf.HasLSMPrograms() || !config.EnableLargeProgs() {
		t.Skip("LSM programs not supported on this kernel")
	}

	crd := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "lsm-valid"
spec:
  lsmhooks:
  - hook: "file_open"
    args:
    - index: 0
      type: "file"
`

	err := checkCrd(t, crd)
	require.NoError(t, err)
}
