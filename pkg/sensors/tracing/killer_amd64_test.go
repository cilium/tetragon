// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build amd64 && linux
// +build amd64,linux

package tracing

import (
	"syscall"
	"testing"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/syscallinfo/i386"
	"github.com/cilium/tetragon/pkg/testutils"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	lc "github.com/cilium/tetragon/pkg/matchers/listmatcher"
)

func TestKillerOverride32(t *testing.T) {
	if !bpf.HasOverrideHelper() {
		t.Skip("skipping killer test, bpf_override_return helper not available")
	}

	test := testutils.RepoRootPath("contrib/tester-progs/killer-tester-32")
	configHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "kill-syscalls"
spec:
  lists:
  - name: "mine"
    type: "syscalls"
    values:
    - "__ia32_sys_prctl"
  killers:
  - syscalls:
    - "list:mine"
  tracepoints:
  - subsystem: "raw_syscalls"
    event: "sys_enter"
    args:
    - index: 4
      type: "syscall64"
    selectors:
    - matchArgs:
      - index: 0
        operator: "InMap"
        values:
        - "list:mine"
      matchBinaries:
      - operator: "In"
        values:
        - "` + test + `"
      matchActions:
      - action: "NotifyKiller"
        argError: -17 # EEXIST
`

	tpChecker := ec.NewProcessTracepointChecker("").
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithSizeArg(i386.SYS_PRCTL),
			)).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_NOTIFYKILLER)

	checker := ec.NewUnorderedEventChecker(tpChecker)

	checkerFunc := func(err error, rc int) {
		if rc != int(syscall.EEXIST) {
			t.Fatalf("Wrong exit code %d expected %d", rc, int(syscall.EEXIST))
		}
	}

	testKiller(t, configHook, test, checker, checkerFunc)
}

func TestKillerSignal32(t *testing.T) {
	if !bpf.HasOverrideHelper() {
		t.Skip("skipping killer test, bpf_override_return helper not available")
	}

	test := testutils.RepoRootPath("contrib/tester-progs/killer-tester-32")
	configHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "kill-syscalls"
spec:
  lists:
  - name: "mine"
    type: "syscalls"
    values:
    - "__ia32_sys_prctl"
  killers:
  - syscalls:
    - "list:mine"
  tracepoints:
  - subsystem: "raw_syscalls"
    event: "sys_enter"
    args:
    - index: 4
      type: "syscall64"
    selectors:
    - matchArgs:
      - index: 0
        operator: "InMap"
        values:
        - "list:mine"
      matchBinaries:
      - operator: "In"
        values:
        - "` + test + `"
      matchActions:
      - action: "NotifyKiller"
        argSig: 9 # SIGKILL
`

	tpChecker := ec.NewProcessTracepointChecker("").
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithSizeArg(i386.SYS_PRCTL),
			)).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_NOTIFYKILLER)

	checker := ec.NewUnorderedEventChecker(tpChecker)

	checkerFunc := func(err error, rc int) {
		if err == nil || err.Error() != "signal: killed" {
			t.Fatalf("Wrong error '%v' expected 'killed'", err)
		}
	}

	testKiller(t, configHook, test, checker, checkerFunc)
}
