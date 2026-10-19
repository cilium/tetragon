// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/bpf"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

func TestUprobeEventConfigCarriesPolicyID(t *testing.T) {
	var state uprobeConfigState
	err := initUprobeArgs(&v1alpha1.UProbeSpec{}, &uprobeHas{}, &addUprobeIn{policyID: 7}, &state)
	require.NoError(t, err)
	require.Equal(t, uint32(7), state.eventConfig.PolicyID)
}

// The enforcer actions are only implemented for kprobes and tracepoints, so
// they have to be rejected here rather than silently do nothing.
func TestUprobeValidationEnforcerAction(t *testing.T) {
	err := checkCrd(t, `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe-notify-enforcer"
spec:
  uprobes:
  - path: "/proc/self/exe"
    symbols: ["main"]
    selectors:
    - matchActions:
      - action: NotifyEnforcer
`)
	require.Error(t, err)
	require.Contains(t, err.Error(), "enforcer actions are not supported")
}

func TestUprobeValidationStackTraceRequiresPost(t *testing.T) {
	tests := []struct {
		name       string
		action     v1alpha1.ActionSelector
		wantErrMsg string
	}{
		{
			name: "kernel stack with Post action",
			action: v1alpha1.ActionSelector{
				Action:           "Post",
				KernelStackTrace: true,
			},
			wantErrMsg: "kernelStackTrace is not supported for uprobes",
		},
		{
			name: "user stack with non-Post action",
			action: v1alpha1.ActionSelector{
				Action:         "NoPost",
				UserStackTrace: true,
			},
			wantErrMsg: "userStackTrace can only be used along Post action",
		},
		{
			name: "user stack with Post action",
			action: v1alpha1.ActionSelector{
				Action:         "Post",
				UserStackTrace: true,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spec := &v1alpha1.UProbeSpec{
				Symbols: []string{"main"},
				Selectors: []v1alpha1.KProbeSelector{{
					MatchActions: []v1alpha1.ActionSelector{test.action},
				}},
			}

			err := validateUprobeSpec(spec, &uprobeConfigState{})
			if test.wantErrMsg != "" {
				require.ErrorContains(t, err, test.wantErrMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestUprobeValidationOverrideMultipleSymbols(t *testing.T) {
	err := checkCrd(t, `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe-multi-override-new-symbol-so-two-targets"
spec:
  uprobes:
  - path: "/proc/self/exe"
    symbols:
    - "first_target"
    - "second_target"
    selectors:
    - matchActions:
      - action: Override
        argNewSymbol: uprobe_test_lib_first_target
`)
	require.Error(t, err)
	require.Contains(t, err.Error(), "only a single uprobe symbol can be redirected")
}

func TestMultiUprobeValidationOverrideSopath(t *testing.T) {
	if !bpf.HasUprobeMulti() {
		t.Skip("skipping sopath validation test for uprobe multi, it is not supported in kernel")
	}
	err := checkCrd(t, `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe-multi-override-new-symbol-so-two-targets"
spec:
  uprobes:
  - path: "/proc/self/exe"
    symbols:
    - "first_target"
    selectors:
    - matchActions:
      - action: Override
        argNewSymbol: uprobe_test_lib_first_target
        sopath: "libuprobe.so"
  - path: "/proc/self/exe"
    symbols:
    - "second_target"
    selectors:
    - matchActions:
      - action: Override
        argNewSymbol: uprobe_test_lib_second_target
        sopath: "libuprobe.so"
`)
	require.Error(t, err)
	require.Contains(t, err.Error(), "multi-uprobes mandate at most a single override action with sopath to be specified in the whole policy")
}
