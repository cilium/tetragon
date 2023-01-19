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

	testNop := testutils.RepoRootPath("contrib/tester-progs/nop")

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

	testExitLeader := testutils.RepoRootPath("contrib/tester-progs/exit-leader")

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

// TestExitZombie tests whether we properly handle the thread group leader exiting before the other threads.
// see: tester-progs/exit-tester.c for the program we use to test this.
//
// The program will:
//   - create a thread
//   - have the group leader return
//   - once this happens, the thread (which continues to run) will exec a /bin/echo command
//
// In our test we check that the parent of the /bin/echo command is the exit-tester program.
func TestExitZombie(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	t.Logf("starting observer")
	obs, err := observer.GetDefaultObserver(t, ctx, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	testBin := testutils.RepoRootPath("contrib/tester-progs/exit-tester")
	testCmd := exec.CommandContext(ctx, testBin)
	testPipes, err := testutils.NewCmdBufferedPipes(testCmd)
	if err != nil {
		t.Fatal(err)
	}
	defer testPipes.Close()

	if err := testCmd.Start(); err != nil {
		t.Fatal(err)
	}

	logWG := testPipes.ParseAndLogCmdOutput(t, nil, nil)
	logWG.Wait()

	if err := testCmd.Wait(); err != nil {
		t.Fatalf("command failed with %s. Context error: %v", err, ctx.Err())
	}

	exitTesterCheck := ec.NewProcessChecker().WithBinary(sm.Suffix("tester-progs/exit-tester"))
	echoCheck := ec.NewProcessChecker().WithBinary(sm.Full("/bin/sh")).WithArguments(sm.Contains("pizza is the best!"))
	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker().WithProcess(exitTesterCheck),
		ec.NewProcessExecChecker().WithProcess(echoCheck).WithParent(exitTesterCheck),
	)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}
