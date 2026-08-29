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

const lsmMatchDataSpec = `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "lsm-match-data"
spec:
  lsmhooks:
  - hook: "file_open"
    data:
    - index: 0
      source: "current_task"
      resolve: "cred.euid.val"
      type: "uint32"
    selectors:
    - matchData:
      - index: 0
        operator: "Equal"
        values:
        - "0"
`

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

func TestLsmValidationMatchData(t *testing.T) {
	_, err := tracingpolicy.FromYAML(lsmMatchDataSpec)
	require.NoError(t, err)
}

func TestAddLsmMatchData(t *testing.T) {
	if !bpf.HasProgramLargeSize() {
		t.Skip("large BPF programs not supported")
	}
	forceLargeProgs(t)

	tp, err := tracingpolicy.FromYAML(lsmMatchDataSpec)
	require.NoError(t, err)
	lsm := &tp.TpSpec().LsmHooks[0]

	id, err := addLsm(lsm, 0, &addLsmIn{policyName: "lsm-match-data"})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := genericLsmTable.RemoveEntry(id)
		require.NoError(t, err)
	})

	entry, err := genericLsmTableGet(id)
	require.NoError(t, err)
	require.Len(t, entry.argPrinters, 1)
	require.True(t, entry.argPrinters[0].data)
	require.Equal(t, uint32(argCurrentTaskBit), entry.config.ArgMeta[0]&argCurrentTaskBit)
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
