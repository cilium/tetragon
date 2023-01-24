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
	"github.com/cilium/tetragon/pkg/jsonchecker"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer"
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

	pidStr := strconv.Itoa(int(observer.GetMyPid()))
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
      type: "int"
    selectors:
    - matchPIDs:
      - operator: In
        values:
        - ` + pidStr

	createCrdFile(t, capabilityhook_)

	obs, err := observer.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
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
				ec.NewKprobeArgumentChecker().WithUserNamespaceArg(ec.NewKprobeUserNamespaceChecker().
					WithOwner(0).
					WithGroup(0),
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
