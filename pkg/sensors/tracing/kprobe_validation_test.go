// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/build"
	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

func checkCrd(t *testing.T, crd string) error {
	tp, err := tracingpolicy.FromYAML(crd)
	if err != nil {
		t.Fatalf("failed to parse tracingpolicy: %s", err)
	}

	_, err = sensors.SensorsFromPolicy(tp, policyfilter.NoFilterID)
	return err
}

func TestValidateSubStringSelectorFeatures(t *testing.T) {
	tests := []struct {
		name          string
		operator      string
		kfunc         string
		selectorSpecs []v1alpha1.KProbeSelector
		macros        map[string]v1alpha1.KProbeSelector
	}{
		{
			name:     "direct SubString selector",
			operator: "SubString",
			kfunc:    "bpf_strnstr",
			selectorSpecs: []v1alpha1.KProbeSelector{{
				MatchArgs: []v1alpha1.ArgSelector{{Operator: "SubString"}},
			}},
		},
		{
			name:     "direct SubStringIgnCase selector",
			operator: "SubStringIgnCase",
			kfunc:    "bpf_strncasestr",
			selectorSpecs: []v1alpha1.KProbeSelector{{
				MatchArgs: []v1alpha1.ArgSelector{{Operator: "SubStringIgnCase"}},
			}},
		},
		{
			name:          "macro SubString selector",
			operator:      "SubString",
			kfunc:         "bpf_strnstr",
			selectorSpecs: []v1alpha1.KProbeSelector{{Macros: []string{"substring"}}},
			macros: map[string]v1alpha1.KProbeSelector{
				"substring": {
					MatchArgs: []v1alpha1.ArgSelector{{Operator: "SubString"}},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.NoError(t, appendMacrosSelectors(test.selectorSpecs, test.macros))
			err := validateSubStringSelectorFeatures(test.selectorSpecs)
			if bpf.HasKfunc(test.kfunc) {
				require.NoError(t, err)
			} else {
				require.EqualError(t, err, "can't use "+test.operator+" operator, no kernel support")
			}
			require.Equal(t, test.operator, test.selectorSpecs[0].MatchArgs[0].Operator)
		})
	}
}

// Without large programs (old kernels or --force-small-progs), the BPF objects
// can't send signals, so Sigkill and Signal actions must be rejected instead of
// silently ignored.
func TestValidateSignalActionsSmallProgs(t *testing.T) {
	forceSmallProgs := option.Config.ForceSmallProgs
	option.Config.ForceSmallProgs = true
	t.Cleanup(func() { option.Config.ForceSmallProgs = forceSmallProgs })

	tests := []struct {
		name    string
		spec    string
		wantErr bool
	}{
		{"kprobe Sigkill", `
  kprobes:
  - call: "sys_getcpu"
    syscall: true
    selectors:
    - matchActions:
      - action: Sigkill`, true},
		{"kprobe Signal", `
  kprobes:
  - call: "sys_getcpu"
    syscall: true
    selectors:
    - matchActions:
      - action: Signal
        argSig: 9`, true},
		{"kprobe return Sigkill", `
  kprobes:
  - call: "sys_getcpu"
    syscall: true
    return: true
    returnArg:
      index: 0
      type: int
    selectors:
    - matchReturnActions:
      - action: Sigkill`, true},
		{"kprobe Sigkill from macro", `
  selectorsMacros:
    kill:
      matchActions:
      - action: Sigkill
  kprobes:
  - call: "sys_getcpu"
    syscall: true
    selectors:
    - macros: ["kill"]`, true},
		{"uprobe Sigkill", `
  uprobes:
  - path: "/proc/self/exe"
    symbols: ["main"]
    selectors:
    - matchActions:
      - action: Sigkill`, true},
		{"tracepoint Sigkill", `
  tracepoints:
  - subsystem: "raw_syscalls"
    event: "sys_enter"
    selectors:
    - matchActions:
      - action: Sigkill`, true},
		{"kprobe Post", `
  kprobes:
  - call: "sys_getcpu"
    syscall: true
    selectors:
    - matchActions:
      - action: Post`, false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := checkCrd(t, "apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: signal-actions\nspec:"+test.spec+"\n")
			if test.wantErr {
				require.ErrorContains(t, err, "sigkill and signal actions require large progs support")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateReturnEntryActions(t *testing.T) {
	post := []v1alpha1.ActionSelector{{Action: "Post"}}
	returnArgs := []v1alpha1.ArgSelector{{Index: 0, Operator: "Equal", Values: []string{"0"}}}
	tests := []struct {
		name          string
		selectorSpecs []v1alpha1.KProbeSelector
		macros        map[string]v1alpha1.KProbeSelector
		hasReturn     bool
		wantErr       string
	}{
		{
			name:          "matchActions with return",
			selectorSpecs: []v1alpha1.KProbeSelector{{MatchReturnActions: post}, {MatchActions: post}},
			hasReturn:     true,
			wantErr:       "selectors[1]: matchActions can't be used with return: true",
		},
		{
			name:          "matchActions added by macro with return",
			selectorSpecs: []v1alpha1.KProbeSelector{{MatchReturnArgs: returnArgs, Macros: []string{"post"}}},
			macros:        map[string]v1alpha1.KProbeSelector{"post": {MatchActions: post}},
			hasReturn:     true,
			wantErr:       "selectors[0]: matchActions can't be used with return: true",
		},
		{
			name:          "matchReturnActions with return",
			selectorSpecs: []v1alpha1.KProbeSelector{{MatchReturnArgs: returnArgs, MatchReturnActions: post}},
			hasReturn:     true,
		},
		{
			name:          "matchActions without return",
			selectorSpecs: []v1alpha1.KProbeSelector{{MatchActions: post}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.NoError(t, appendMacrosSelectors(test.selectorSpecs, test.macros))
			err := validateReturnEntryActions(test.selectorSpecs, test.hasReturn)
			if test.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, test.wantErr)
			}
		})
	}
}

func TestKprobeValidationReturnEntryActions(t *testing.T) {
	crd := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "return-entry-actions"
spec:
  kprobes:
  - call: "sys_getcpu"
    syscall: true
    return: true
    returnArg:
      index: 0
      type: int
    selectors:
    - matchActions:
      - action: Override
        argError: -1
`

	err := checkCrd(t, crd)
	require.ErrorContains(t, err, "selectors[0]: matchActions can't be used with return: true")
}

func TestValidateReturnSelectors(t *testing.T) {
	returnArgs := []v1alpha1.ArgSelector{{Index: 0, Operator: "Equal", Values: []string{"0"}}}
	actions := []v1alpha1.ActionSelector{{Action: "Post"}}
	tests := []struct {
		name          string
		selectorSpecs []v1alpha1.KProbeSelector
		macros        map[string]v1alpha1.KProbeSelector
		hasReturn     bool
		wantErr       string
	}{
		{
			name:          "matchReturnArgs without return",
			selectorSpecs: []v1alpha1.KProbeSelector{{}, {MatchReturnArgs: returnArgs}},
			wantErr:       "selectors[1]: matchReturnArgs requires return: true",
		},
		{
			name:          "matchReturnActions without return",
			selectorSpecs: []v1alpha1.KProbeSelector{{MatchReturnActions: actions}},
			wantErr:       "selectors[0]: matchReturnActions requires return: true",
		},
		{
			name:          "matchReturnArgs added by macro without return",
			selectorSpecs: []v1alpha1.KProbeSelector{{Macros: []string{"ret"}}},
			macros:        map[string]v1alpha1.KProbeSelector{"ret": {MatchReturnArgs: returnArgs}},
			wantErr:       "selectors[0]: matchReturnArgs requires return: true",
		},
		{
			name:          "return selectors with return",
			selectorSpecs: []v1alpha1.KProbeSelector{{MatchReturnArgs: returnArgs, MatchReturnActions: actions}},
			hasReturn:     true,
		},
		{
			name:          "entry selectors without return",
			selectorSpecs: []v1alpha1.KProbeSelector{{MatchActions: actions}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.NoError(t, appendMacrosSelectors(test.selectorSpecs, test.macros))
			err := validateReturnSelectors(test.selectorSpecs, test.hasReturn)
			if test.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, test.wantErr)
			}
		})
	}
}

func TestKprobeValidationReturnSelectorsWithoutReturn(t *testing.T) {
	crd := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "return-selectors-without-return"
spec:
  kprobes:
  - call: "sys_getcpu"
    syscall: true
    selectors:
    - matchReturnArgs:
      - index: 0
        operator: Equal
        values: ["0"]
`

	err := checkCrd(t, crd)
	require.ErrorContains(t, err, "selectors[0]: matchReturnArgs requires return: true")
}

func TestKprobeValidationListWrongSyscallName(t *testing.T) {
	// messed up syscall name in the list
	crd := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "list-syscalls"
spec:
  lists:
  - name: "syscalls"
    type: "syscalls"
    values:
    - "sys_dupXXX"
  kprobes:
  - call: "list:syscalls"
`

	err := checkCrd(t, crd)
	require.Error(t, err)
}

func TestKprobeValidationListWrongOverride(t *testing.T) {
	// override on non override-able functions in list
	crd := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "list-syscalls"
spec:
  lists:
  - name: "syscalls"
    type: "syscalls"
    values:
    - "ksys_read"
    - "ksys_write"
  kprobes:
  - call: "list:syscalls"
    selectors:
    - matchActions:
      - action: Override
        argError: -1
`

	err := checkCrd(t, crd)
	require.Error(t, err)
}

func TestKprobeValidationListWrongName(t *testing.T) {
	// wrong list name reference in kprobe's call
	crd := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "list-syscalls"
spec:
  lists:
  - name: "syscalls"
    type: "syscalls"
    values:
    - "sys_dup"
    - "sys_dup2"
  kprobes:
  - call: "list:wrongname"
`

	err := checkCrd(t, crd)
	require.Error(t, err)
}

func TestKprobeValidationListGeneratedSyscallsNotEmpty(t *testing.T) {
	// not empty values for generated syscalls list
	crd := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "list-syscalls"
spec:
  lists:
  - name: "syscalls"
    type: "generated_syscalls"
    values:
    - "sys_dup"
    - "sys_dup2"
  kprobes:
  - call: "list:syscalls"
`

	err := checkCrd(t, crd)
	require.Error(t, err)
}

func TestKprobeValidationListGeneratedFtraceNotEmpty(t *testing.T) {
	// not empty values for generated ftrace list
	crd := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "list-syscalls"
spec:
  lists:
  - name: "ftrace"
    type: "generated_ftrace"
    values:
    - "ksys_read"
    - "ksys_write"
  kprobes:
  - call: "list:ftrace"
`

	err := checkCrd(t, crd)
	require.Error(t, err)
}

func TestKprobeValidationListGeneratedFtraceNoPattern(t *testing.T) {
	// no pattern specified for generated ftrace list
	crd := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "list-syscalls"
spec:
  lists:
  - name: "ftrace"
    type: "generated_ftrace"
  kprobes:
  - call: "list:ftrace"
`

	err := checkCrd(t, crd)
	require.Error(t, err)
}
func TestKprobeValidationWrongSyscallName(t *testing.T) {
	// messed up syscall name in kprobe's call
	crd := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "list-syscalls"
spec:
  kprobes:
  - call: "sys_dupXXX"
`

	err := checkCrd(t, crd)
	require.Error(t, err)
}

func TestKprobeValidationWrongOverride(t *testing.T) {
	// override on non override-able functions in list
	crd := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "list-syscalls"
spec:
  kprobes:
  - call: "ksys_read"
    selectors:
    - matchActions:
      - action: Override
        argError: -1
`

	err := checkCrd(t, crd)
	require.Error(t, err)
}

func TestKprobeValidationNonSyscallOverride(t *testing.T) {
	// override on non syscall (non override-able) function
	crd := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "override-non-syscall"
spec:
  kprobes:
  - call: "close_fd"
    syscall: false
    args:
    - index: 0
      type: "int"
    selectors:
    - matchActions:
      - action: Override
        argError: -2
`

	err := checkCrd(t, crd)
	require.Error(t, err)

}

func forceLargeProgs(t *testing.T) {
	t.Helper()

	origForceLargeProgs := option.Config.ForceLargeProgs
	origForceSmallProgs := option.Config.ForceSmallProgs
	option.Config.ForceLargeProgs = true
	option.Config.ForceSmallProgs = false
	t.Cleanup(func() {
		option.Config.ForceLargeProgs = origForceLargeProgs
		option.Config.ForceSmallProgs = origForceSmallProgs
	})
}

func TestKprobeValidationReturnArgActionSocketTracking(t *testing.T) {
	forceLargeProgs(t)

	tests := []struct {
		name   string
		action string
	}{
		{name: "tracksock", action: "TrackSock"},
		{name: "untracksock", action: "UntrackSock"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kp := &v1alpha1.KProbeSpec{
				Call:            "sys_dup",
				Syscall:         true,
				Return:          true,
				ReturnArg:       &v1alpha1.KProbeArg{Index: 0, Type: "int"},
				ReturnArgAction: tt.action,
			}
			in := &addKprobeIn{policyName: "return-arg-action-" + tt.name}

			id, err := addKprobe("sys_dup", 0, kp, in, hasMaps{})
			require.NoError(t, err)
			t.Cleanup(func() {
				_, err := genericKprobeTable.RemoveEntry(id)
				require.NoError(t, err)
			})
		})
	}
}

func TestKprobeValidationReturnArgActionPost(t *testing.T) {
	forceLargeProgs(t)

	kp := &v1alpha1.KProbeSpec{
		Call:            "sys_dup",
		Syscall:         true,
		Return:          true,
		ReturnArg:       &v1alpha1.KProbeArg{Index: 0, Type: "int"},
		ReturnArgAction: "Post",
	}
	in := &addKprobeIn{policyName: "return-arg-action-post"}

	_, err := addKprobe("sys_dup", 0, kp, in, hasMaps{})
	require.ErrorContains(t, err, "omit returnArgAction or use 'TrackSock'/'UntrackSock'")
}

func TestKprobeValidationReturnArgActionInvalid(t *testing.T) {
	forceLargeProgs(t)

	kp := &v1alpha1.KProbeSpec{
		Call:            "sys_dup",
		Syscall:         true,
		Return:          true,
		ReturnArg:       &v1alpha1.KProbeArg{Index: 0, Type: "int"},
		ReturnArgAction: "Bogus",
	}
	in := &addKprobeIn{policyName: "return-arg-action-invalid"}

	_, err := addKprobe("sys_dup", 0, kp, in, hasMaps{})
	require.ErrorContains(t, err, "ReturnArgAction type 'Bogus' unsupported")
}

func TestKprobeLTOp(t *testing.T) {
	// missing returnArg while having return: true
	crd := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "missing-returnarg"
spec:
  kprobes:
  - call: "sys_openat"
    args:
    - index: 0
      type: int
    selectors:
    - matchArgs:
      - index: 0
        operator: "LT"
        values:
        - "0"
`

	err := checkCrd(t, crd)
	if config.EnableLargeProgs() {
		require.NoError(t, err)
	} else {
		require.Error(t, err)
	}
}

func TestKprobeGTOp(t *testing.T) {
	// missing returnArg while having return: true
	crd := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "missing-returnarg"
spec:
  kprobes:
  - call: "sys_openat"
    args:
    - index: 0
      type: int
    selectors:
    - matchArgs:
      - index: 0
        operator: "GT"
        values:
        - "0"
`

	err := checkCrd(t, crd)
	if config.EnableLargeProgs() {
		require.NoError(t, err)
	} else {
		require.Error(t, err)
	}
}

// Test that tracing policy max tags
func TestTracingPolicyTagsMax(t *testing.T) {
	// NB: validation tests require k8s
	build.SkipIfK8sDisabled(t)
	// Ensure that CRD fail if tags > 16
	crd1 := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "file-install"
spec:
  kprobes:
  - call: "fd_install"
    syscall: false
    tags: [ "01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11", "12", "13", "14", "15", "16", "17" ]
 `

	crd2 := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "file-install"
spec:
  kprobes:
  - call: "fd_install"
    syscall: false
    tags: [ "01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11", "12", "13", "14", "15", "16" ]
 `

	crd3 := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "file-install"
spec:
  kprobes:
  - call: "fd_install"
    syscall: false
 `

	_, err := tracingpolicy.FromYAML(crd1)
	require.Error(t, err)

	_, err = tracingpolicy.FromYAML(crd2)
	require.NoError(t, err)

	_, err = tracingpolicy.FromYAML(crd3)
	require.NoError(t, err)
}

func TestKprobeMultiSymbolInstancesFail(t *testing.T) {
	if !bpf.HasKprobeMulti() {
		t.Skip("Test requires kprobe multi")
	}

	crd := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "multiple-symbols"
spec:
  kprobes:
  - call: sys_prctl
    syscall: true
  - call: sys_prctl
    syscall: true
`

	err := checkCrd(t, crd)
	require.Error(t, err)
}
