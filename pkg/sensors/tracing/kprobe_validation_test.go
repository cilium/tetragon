// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"testing"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/stretchr/testify/assert"
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
	assert.Error(t, err)
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
	assert.Error(t, err)
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
	assert.Error(t, err)
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
	assert.Error(t, err)
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
	assert.Error(t, err)
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
	assert.Error(t, err)
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
	assert.Error(t, err)
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
	assert.Error(t, err)
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
	assert.Error(t, err)

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
	assert.Error(t, err)
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
        - 0
`

	err := checkCrd(t, crd)
	if config.EnableLargeProgs() {
		assert.NoError(t, err)
	} else {
		assert.Error(t, err)
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
        - 0
`

	err := checkCrd(t, crd)
	if config.EnableLargeProgs() {
		assert.NoError(t, err)
	} else {
		assert.Error(t, err)
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
	assert.Error(t, err)

	_, err = tracingpolicy.FromYAML(crd2)
	assert.NoError(t, err)

	_, err = tracingpolicy.FromYAML(crd3)
	assert.NoError(t, err)
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
	assert.Error(t, err)
}
