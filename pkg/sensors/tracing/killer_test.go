// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"context"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"testing"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	lc "github.com/cilium/tetragon/pkg/matchers/listmatcher"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/testutils"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/stretchr/testify/assert"
)

func test_killer(t *testing.T, configHook string, test string,
	checker *eventchecker.UnorderedEventChecker,
	checkerFunc func(err error, rc int)) {

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	err := os.WriteFile(testConfigFile, []byte(configHook), 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	cmd := exec.Command(test)
	err = cmd.Run()

	checkerFunc(err, cmd.ProcessState.ExitCode())

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestKillerOverride(t *testing.T) {
	if !bpf.HasOverrideHelper() {
		t.Skip("skipping killer test, bpf_override_return helper not available")
	}

	test := testutils.RepoRootPath("contrib/tester-progs/killer-tester")
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
    - "sys_prctl"
  killers:
  - syscalls:
    - "list:mine"
  tracepoints:
  - subsystem: "raw_syscalls"
    event: "sys_enter"
    args:
    - index: 4
      type: "uint64"
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
				ec.NewKprobeArgumentChecker().WithSizeArg(syscall.SYS_PRCTL),
			)).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_NOTIFYKILLER)

	checker := ec.NewUnorderedEventChecker(tpChecker)

	checkerFunc := func(err error, rc int) {
		if rc != int(syscall.EEXIST) {
			t.Fatalf("Wrong exit code %d expected %d", rc, int(syscall.EEXIST))
		}
	}

	test_killer(t, configHook, test, checker, checkerFunc)
}

func TestKillerSignal(t *testing.T) {
	if !bpf.HasOverrideHelper() {
		t.Skip("skipping killer test, bpf_override_return helper not available")
	}

	test := testutils.RepoRootPath("contrib/tester-progs/killer-tester")
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
    - "sys_prctl"
  killers:
  - syscalls:
    - "list:mine"
  tracepoints:
  - subsystem: "raw_syscalls"
    event: "sys_enter"
    args:
    - index: 4
      type: "uint64"
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
				ec.NewKprobeArgumentChecker().WithSizeArg(syscall.SYS_PRCTL),
			)).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_NOTIFYKILLER)

	checker := ec.NewUnorderedEventChecker(tpChecker)

	checkerFunc := func(err error, rc int) {
		if err == nil || err.Error() != "signal: killed" {
			t.Fatalf("Wrong error '%v' expected 'killed'", err)
		}
	}

	test_killer(t, configHook, test, checker, checkerFunc)
}

func TestKillerMulti(t *testing.T) {
	if !bpf.HasOverrideHelper() {
		t.Skip("skipping killer test, bpf_override_return helper not available")
	}

	crd := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "kill-syscalls"
spec:
  lists:
  - name: "mine1"
    type: "syscalls"
    values:
    - "sys_prctl"
  - name: "mine2"
    type: "syscalls"
    values:
    - "sys_prctl"
  killers:
  - syscalls:
    - "list:mine1"
  - syscalls:
    - "list:mine2"
  tracepoints:
  - subsystem: "raw_syscalls"
    event: "sys_enter"
    args:
    - index: 4
      type: "uint64"
    selectors:
    - matchArgs:
      - index: 0
        operator: "InMap"
        values:
        - "list:mine1"
      matchActions:
      - action: "NotifyKiller"
        argSig: 9 # SIGKILL
`

	err := checkCrd(t, crd)
	assert.Error(t, err)
}
