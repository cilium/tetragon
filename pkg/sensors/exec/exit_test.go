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
	"github.com/sirupsen/logrus"
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

	var startTime, exitTime time.Time

	// The test executes 'exit-leader' benary which spawns a thread and
	// exits the leader immediately while the new thread continues to
	// run for 3 seconds and exits. We verify that we get exit event 3
	// seconds after the start.

	nextCheck := func(event ec.Event, l *logrus.Logger) (bool, error) {
		switch ev := event.(type) {
		case *tetragon.ProcessExec:
			if ev.Process.Binary == testExitLeader {
				startTime = ev.Process.StartTime.AsTime()
			}
			return false, nil
		case *tetragon.ProcessExit:
			if ev.Process.Binary == testExitLeader {
				exitTime = ev.Time.AsTime()
			}
			return false, nil
		}
		return false, nil
	}

	finalCheck := func(l *logrus.Logger) error {
		delta := exitTime.Sub(startTime)

		fmt.Printf("execTime %v\n", startTime)
		fmt.Printf("exitTime %v\n", exitTime)
		fmt.Printf("delta %v\n", delta)

		if delta < 3*time.Second {
			return fmt.Errorf("unexpected delta < 3 seconds")
		}
		return nil
	}

	checker := &ec.FnEventChecker{
		NextCheckFn:  nextCheck,
		FinalCheckFn: finalCheck,
	}

	if err := exec.Command(testExitLeader).Run(); err != nil {
		t.Fatalf("Failed to execute test binary: %s\n", err)
	}

	if err := jsonchecker.JsonTestCheck(t, checker); err != nil {
		t.Logf("error: %s", err)
		t.Fail()
	}
}
