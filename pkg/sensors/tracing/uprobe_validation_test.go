// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/policyconf"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/selectors"
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

func TestUprobeValidationReturnArgsWithActions(t *testing.T) {
	err := checkCrd(t, `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe-return-args-actions"
spec:
  uprobes:
  - path: "/proc/self/exe"
    symbols: ["main"]
    return: true
    returnArg:
      index: 0
      type: int
    selectors:
    - matchReturnArgs:
      - index: 0
        operator: Equal
        values: ["0"]
      matchActions:
      - action: Post
`)
	require.ErrorContains(t, err, "selectors[0]: matchActions can't be combined with matchReturnArgs")
}

func TestUprobeValidationReturnSelectorsWithoutReturn(t *testing.T) {
	err := checkCrd(t, `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe-return-selectors-without-return"
spec:
  uprobes:
  - path: "/proc/self/exe"
    symbols: ["main"]
    selectors:
    - matchReturnActions:
      - action: Post
`)
	require.ErrorContains(t, err, "selectors[0]: matchReturnActions requires return: true")
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

func TestUprobeReturnOverridePolicyMode(t *testing.T) {
	for _, tc := range []struct {
		mode string
		want policyconf.Mode
	}{
		{"", policyconf.EnforceMode},
		{"enforce", policyconf.EnforceMode},
		{"monitor", policyconf.MonitorMode},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			spec := &v1alpha1.TracingPolicySpec{UProbes: []v1alpha1.UProbeSpec{{
				Selectors: []v1alpha1.KProbeSelector{{MatchReturnActions: []v1alpha1.ActionSelector{{Action: "Override"}}}},
			}}}
			if tc.mode != "" {
				spec.Options = []v1alpha1.OptionSpec{{Name: "policy-mode", Value: tc.mode}}
			}
			pi, err := newPolicyInfoFromSpec("", "", "return-override", policyfilter.NoFilterID, spec, nil)
			require.NoError(t, err)
			require.Equal(t, tc.want, pi.specOpts.policyMode)
		})
	}
}

func TestUprobeReturnSensorMaps(t *testing.T) {
	spec := &v1alpha1.UProbeSpec{
		Symbols: []string{"crypt"}, Return: true,
		ReturnArg: &v1alpha1.KProbeArg{Index: 0, Type: "string"},
		Selectors: []v1alpha1.KProbeSelector{{
			MatchReturnArgs:    []v1alpha1.ArgSelector{{Index: 0, Operator: "Equal", Values: []string{"*"}}},
			MatchReturnActions: []v1alpha1.ActionSelector{{Action: "Override", ArgError: 0}},
		}},
	}
	var state uprobeConfigState
	require.NoError(t, initUprobeSelectors(spec, &addUprobeIn{selMaps: &selectors.KernelSelectorMaps{}}, &state, nil, 0, &uprobeHas{}))
	defer selectors.CleanupKernelSelectorState(state.selectors.entry)
	defer selectors.CleanupKernelSelectorState(state.selectors.retrn)
	pi := &policyInfo{name: "return-override"}
	entry := &genericUprobe{symbol: "crypt", loadArgs: uprobeLoadArgs{selectors: state.selectors, retprobe: true}}
	progs, maps := createUprobeSensorFromEntry(pi, entry, nil, nil, uprobeHas{})
	// progs[0] is the entry uprobe program, progs[1] its return (uretprobe) program.
	require.Len(t, progs, 2)
	require.Contains(t, progs[1].PinMap, "string_maps_0")
	// The first program to request a policy map owns it. The entry program
	// must own policy_conf: the owner writes the policy mode while it loads,
	// and the entry program is attached before the return program loads.
	// selector_stats is created the same way, so check its owner too.
	require.Same(t, progs[0], pi.policyConf.Prog)
	require.Same(t, progs[0], pi.selectorStats.Prog)
	for _, name := range []string{"policy_conf", "selector_stats"} {
		var users int
		for _, m := range maps {
			if m.Name == name && !m.Owner {
				users++
			}
		}
		require.Equal(t, 1, users, name)
	}
}
