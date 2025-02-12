// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build amd64 && linux
// +build amd64,linux

package tracing

import (
	"context"
	"strconv"
	"sync"
	"syscall"
	"testing"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/arch"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/kernels"
	lc "github.com/cilium/tetragon/pkg/matchers/listmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/reader/caps"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"

	_ "github.com/cilium/tetragon/pkg/sensors/exec"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func TestKprobeTraceCapabilityChecks(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	t.Logf("tester pid=%s\n", pidStr)

	capabilityhook_ := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "trace-capability-checks"
spec:
  kprobes:
  - call: "cap_capable"
    syscall: false
    return: true
    args:
    - index: 0
      type: "nop"
    - index: 1
      type: "user_namespace"
    - index: 2
      type: "capability"
    returnArg:
      index: 0
      type: "int"
    selectors:
    - matchPIDs:
      - operator: In
        values:
        - ` + pidStr

	createCrdFile(t, capabilityhook_)

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	capName, err := caps.GetCapability(unix.CAP_SYS_RAWIO)
	if err != nil {
		t.Fatalf("GetCapability() error: %s", err)
	}

	// Match only owner and group of userns as we are supposed to be real root
	kpChecker := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full("cap_capable")).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_POST).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithValues(
				ec.NewKprobeArgumentChecker().WithUserNsArg(ec.NewUserNamespaceChecker().
					WithUid(0).
					WithGid(0),
				),
				ec.NewKprobeArgumentChecker().WithCapabilityArg(ec.NewKprobeCapabilityChecker().
					WithValue(unix.CAP_SYS_RAWIO).
					WithName(sm.Full(capName)),
				),
			),
		)

	checker := ec.NewUnorderedEventChecker(kpChecker)

	io_delay := 0x80
	// probe IO_DELAY to trigger a CAP_SYS_RAWIO check, this is for x86
	err = syscall.Ioperm(io_delay, 1, 1)
	if err != nil {
		t.Logf("Failed to ioperm(0x%02x): %v\n", io_delay, err)
		t.Fatal()
	}

	t.Logf("ioperm() enabling 0x%02x succeeded", io_delay)

	// disable port
	syscall.Ioperm(io_delay, 1, 0)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestKprobeListSyscallDups(t *testing.T) {
	if !kernels.MinKernelVersion("5.3.0") {
		t.Skip("TestCopyFd requires at least 5.3.0 version")
	}
	myPid := observertesthelper.GetMyPid()
	pidStr := strconv.Itoa(int(myPid))
	configHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "sys-dups"
spec:
  lists:
  - name: "test"
    type: "syscalls"
    values:
    - "sys_dup"
    - "sys_dup2"
    - "sys_dup3"
  kprobes:
  - call: "list:test"
    args:
    - index: 0
      type: "int"
    selectors:
    - matchPIDs:
      - operator: In
        followForks: true
        isNamespacePID: false
        values:
        - ` + pidStr + `
      matchArgs:
      - index: 0
        operator: "Equal"
        values:
        - 9999
`

	// The test hooks sys_dup[23] syscalls through the list and
	// makes sure we receive events for all of them.

	kpCheckerDup := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full(arch.AddSyscallPrefixTestHelper(t, "sys_dup"))).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(int32(9999)),
			))

	kpCheckerDup2 := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full(arch.AddSyscallPrefixTestHelper(t, "sys_dup2"))).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(int32(9999)),
			))

	kpCheckerDup3 := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full(arch.AddSyscallPrefixTestHelper(t, "sys_dup3"))).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(int32(9999)),
			))

	checker := ec.NewUnorderedEventChecker(kpCheckerDup, kpCheckerDup2, kpCheckerDup3)

	testListSyscallsDups(t, checker, configHook)
}
