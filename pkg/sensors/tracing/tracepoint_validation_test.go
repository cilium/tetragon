// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"testing"

	"github.com/stretchr/testify/require"
)

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
