// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

func checkCrd(t *testing.T, crd string) error {
	tp, err := tracingpolicy.FromYAML(crd)
	if err != nil {
		t.Fatalf("failed to parse tracingpolicy: %s", err)
	}

	_, err = sensors.GetMergedSensorFromParserPolicy(tp)
	return err
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

func TestKprobeValidationMissingReturnArg(t *testing.T) {

	// missing returnArg while having return: true

	crd := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "missing-returnarg"
spec:
  kprobes:
  - call: "sys_openat"
    return: true
    syscall: true
`

	err := checkCrd(t, crd)
	require.Error(t, err)
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

func TestTracepointValidationWrongSubsystem(t *testing.T) {

	crd := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tp-bogus-subsystem"
spec:
  tracepoints:
  - subsystem: "bogus_subsystem"
    event: "bogus_event"
`

	err := checkCrd(t, crd)
	require.Error(t, err)
}

func TestTracepointValidationWrongEvent(t *testing.T) {

	crd := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tp-bogus-event"
spec:
  tracepoints:
  - subsystem: "syscalls"
    event: "bogus_event_xyz"
`

	err := checkCrd(t, crd)
	require.Error(t, err)
}

func TestTracepointValidationEmptySubsystem(t *testing.T) {

	crd := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tp-empty-subsystem"
spec:
  tracepoints:
  - subsystem: ""
    event: "sys_enter_openat"
`

	err := checkCrd(t, crd)
	require.Error(t, err)
}

func TestTracepointValidationEmptyEvent(t *testing.T) {

	crd := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tp-empty-event"
spec:
  tracepoints:
  - subsystem: "syscalls"
    event: ""
`

	err := checkCrd(t, crd)
	require.Error(t, err)
}

func TestTracepointValidationArgIndexOutOfBounds(t *testing.T) {

	crd := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tp-arg-oob"
spec:
  tracepoints:
  - subsystem: "syscalls"
    event: "sys_enter_openat"
    args:
    - index: 999
      type: "int"
`

	err := checkCrd(t, crd)
	require.Error(t, err)
}

func TestTracepointValidationRawArgIndexOutOfBounds(t *testing.T) {

	crd := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tp-raw-arg-oob"
spec:
  tracepoints:
  - subsystem: "raw_syscalls"
    event: "sys_enter"
    raw: true
    args:
    - index: 6
      type: "int"
`

	err := checkCrd(t, crd)
	require.Error(t, err)
}

func TestTracepointValidationValidPolicy(t *testing.T) {

	crd := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tp-valid"
spec:
  tracepoints:
  - subsystem: "raw_syscalls"
    event: "sys_enter"
    raw: true
    args:
    - index: 4
      type: "syscall64"
`

	err := checkCrd(t, crd)
	require.NoError(t, err)
}

func TestTracepointValidationNotifyEnforcerWithoutEnforcer(t *testing.T) {

	crd := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tp-enforcer-missing"
spec:
  tracepoints:
  - subsystem: "raw_syscalls"
    event: "sys_enter"
    args:
    - index: 4
      type: "syscall64"
    selectors:
    - matchActions:
      - action: NotifyEnforcer
`

	err := checkCrd(t, crd)
	require.Error(t, err)
}

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
