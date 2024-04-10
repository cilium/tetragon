// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build amd64 && linux
// +build amd64,linux

package tracing

import (
	"context"
	"os"
	"strconv"
	"sync"
	"syscall"
	"testing"

	"github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/kernels"
	lc "github.com/cilium/tetragon/pkg/matchers/listmatcher"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/stretchr/testify/assert"
)

func testListSyscallsDups(t *testing.T, checker *eventchecker.UnorderedEventChecker, configHook string) {
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

	syscall.Dup(9999)
	syscall.Dup2(9999, 2222)
	syscall.Dup3(9999, 2222, 0)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestTracepointListSyscallDupsEqual(t *testing.T) {
	if !kernels.MinKernelVersion("5.3.0") {
		t.Skip("TestTracepointListSyscallDupsEqual requires at least 5.3.0 version")
	}

	myPid := observertesthelper.GetMyPid()
	pidStr := strconv.Itoa(int(myPid))
	configHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "sys-write"
spec:
  lists:
  - name: "test"
    type: "syscalls"
    values:
    - "sys_dup"
    - "sys_dup2"
    - "sys_dup3"
  tracepoints:
  - subsystem: "raw_syscalls"
    event: "sys_enter"
    args:
    - index: 4
      type: "syscall64"
    - index: 5
      type: "uint64"
    selectors:
    - matchPIDs:
      - operator: In
        followForks: true
        isNamespacePID: false
        values:
        - ` + pidStr + `
      matchArgs:
      - index: 4
        operator: "InMap"
        values:
        - "list:test"
      - index: 5
        operator: "Equal"
        values:
        - 9999
`

	// The test hooks raw tracepoint and uses InMap operator with list
	// specified as its value to get only dup[23] syscall events.

	tpCheckerDup := ec.NewProcessTracepointChecker("").
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithSizeArg(syscall.SYS_DUP),
				ec.NewKprobeArgumentChecker().WithSizeArg(9999),
			))

	tpCheckerDup2 := ec.NewProcessTracepointChecker("").
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithSizeArg(syscall.SYS_DUP2),
				ec.NewKprobeArgumentChecker().WithSizeArg(9999),
			))

	tpCheckerDup3 := ec.NewProcessTracepointChecker("").
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithSizeArg(syscall.SYS_DUP3),
				ec.NewKprobeArgumentChecker().WithSizeArg(9999),
			))

	checker := ec.NewUnorderedEventChecker(tpCheckerDup, tpCheckerDup2, tpCheckerDup3)

	testListSyscallsDups(t, checker, configHook)
}
