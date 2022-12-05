package exec

import (
	"context"
	"fmt"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/testutils"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/stretchr/testify/assert"
)

func TestExit(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	obs, err := observer.GetDefaultObserver(t, ctx, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("Failed to run observer: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	testNop := testutils.ContribPath("tester-progs/nop")

	procChecker := ec.NewProcessChecker().
		WithBinary(sm.Full(testNop))

	execChecker := ec.NewProcessExecChecker().WithProcess(procChecker)
	exitChecker := ec.NewProcessExitChecker().WithProcess(procChecker)

	var checker *ec.UnorderedEventChecker

	checker = ec.NewUnorderedEventChecker(execChecker, exitChecker)

	if err := exec.Command(testNop).Run(); err != nil {
		t.Fatalf("Failed to execute test binary: %s\n", err)
	}

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestExitLeader(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	obs, err := observer.GetDefaultObserver(t, ctx, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("Failed to run observer: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	testExitLeader := testutils.ContribPath("tester-progs/exit-leader")

	procChecker := ec.NewProcessChecker().
		WithBinary(sm.Full(testExitLeader))

	execChecker := ec.NewProcessExecChecker().WithProcess(procChecker)
	exitChecker := ec.NewProcessExitChecker().WithProcess(procChecker)

	var checker *ec.UnorderedEventChecker

	checker = ec.NewUnorderedEventChecker(execChecker, exitChecker)

	if err := exec.Command(testExitLeader).Run(); err != nil {
		t.Fatalf("Failed to execute test binary: %s\n", err)
	}

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)

	checker = ec.NewUnorderedEventChecker(exitChecker)

	var response *tetragon.GetEventsResponse

	response, err = jsonchecker.JsonTestFind(t, checker)
	assert.NoError(t, err)

	exitEvent, ok := response.Event.(*tetragon.GetEventsResponse_ProcessExit)
	if !ok {
		t.Fatalf("Failed to find exit event\n")
	}

	execTime := exitEvent.ProcessExit.Process.StartTime.AsTime()
	exitTime := exitEvent.ProcessExit.Time.AsTime()
	delta := exitTime.Sub(execTime)

	fmt.Printf("execTime %v\n", execTime)
	fmt.Printf("exitTime %v\n", exitTime)
	fmt.Printf("delta %v\n", delta)

	if delta < 3*time.Second {
		t.Fatalf("Exit event too soon\n")
	}
}
