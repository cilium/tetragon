// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"testing"

	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/stretchr/testify/assert"
)

func checkCrd(t *testing.T, crd string) error {
	tp, err := tracingpolicy.PolicyFromYAML(crd)
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
