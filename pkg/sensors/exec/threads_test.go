// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package exec

import (
	"context"
	"os/exec"
	"strings"
	"sync"
	"testing"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	grpcexec "github.com/cilium/tetragon/pkg/grpc/exec"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/logger"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors/exec/procevents"
	testsensor "github.com/cilium/tetragon/pkg/sensors/test"
	"github.com/cilium/tetragon/pkg/testutils"
	"github.com/cilium/tetragon/pkg/testutils/perfring"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sampleThreadTesterOutput = `
parent:		(pid:143563, tid:143563, ppid:7860)	starts
Thread 1:	(pid:143564, tid:143565, ppid:143563)	open("/etc/issue") succeeded
Child 1:	(pid:143564, tid:143564, ppid:143563)	open("/etc/issue") succeeded
parent:		(pid:143563, tid:143563, ppid:7860)	child1 (143564) exited with: 0
`

func TestThreadTesterParser(t *testing.T) {
	cti := &testutils.ThreadTesterInfo{}
	for _, l := range strings.Split(sampleThreadTesterOutput, "\n") {
		cti.ParseLine(l)
	}

	assert.Equal(t, uint32(143563), cti.ParentPid)
	assert.Equal(t, cti.ParentPid, cti.ParentTid)
	assert.Equal(t, uint32(143564), cti.Child1Pid)
	assert.Equal(t, cti.Child1Pid, cti.Child1Tid)
	assert.Equal(t, cti.ParentPid, cti.ParentChild1Pid)
	assert.Equal(t, uint32(143564), cti.Thread1Pid)
	assert.Equal(t, uint32(143565), cti.Thread1Tid)
	assert.Equal(t, cti.ParentPid, cti.ParentThread1Pid)
}

func TestCloneThreadsTester(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	testBinPath := "contrib/tester-progs/threads-tester"
	testBin := testutils.RepoRootPath(testBinPath)
	testCmd := exec.CommandContext(ctx, testBin)
	testPipes, err := testutils.NewCmdBufferedPipes(testCmd)
	if err != nil {
		t.Fatal(err)
	}
	defer testPipes.Close()

	t.Logf("starting observer")
	obs, err := observertesthelper.GetDefaultObserver(t, ctx, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	tti := &testutils.ThreadTesterInfo{}
	if err := testCmd.Start(); err != nil {
		t.Fatal(err)
	}
	logWG := testPipes.ParseAndLogCmdOutput(t, tti.ParseLine, nil)
	logWG.Wait()
	if err := testCmd.Wait(); err != nil {
		t.Fatalf("command failed with %s. Context error: %v", err, ctx.Err())
	}

	tti.AssertPidsTids(t)
}

func TestMatchCloneThreadsIDs(t *testing.T) {
	testutils.CaptureLog(t, logger.GetLogger().(*logrus.Logger))
	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	if err := observer.InitDataCache(1024); err != nil {
		t.Fatalf("observertesthelper.InitDataCache: %s", err)
	}

	option.Config.HubbleLib = tus.Conf().TetragonLib
	tus.LoadInitialSensor(t)

	if err := procevents.GetRunningProcs(); err != nil {
		t.Fatalf("procevents.GetRunningProcs: %s", err)
	}

	tus.LoadSensor(t, testsensor.GetTestSensor())

	testBinPath := "contrib/tester-progs/threads-tester"
	testBin := testutils.RepoRootPath(testBinPath)

	tti := &testutils.ThreadTesterInfo{}
	ops := func() {
		testCmd := exec.CommandContext(ctx, testBin)
		testPipes, err := testutils.NewCmdBufferedPipes(testCmd)
		if err != nil {
			t.Fatal(err)
		}
		defer testPipes.Close()

		if err := testCmd.Start(); err != nil {
			t.Fatal(err)
		}
		logWG := testPipes.ParseAndLogCmdOutput(t, tti.ParseLine, nil)
		logWG.Wait()
		if err := testCmd.Wait(); err != nil {
			t.Fatalf("command failed with %s. Context error: %v", err, ctx.Err())
		}
	}

	cloneEvents := []*grpcexec.MsgCloneEventUnix{}

	execPID, execTID := uint32(0), uint32(0)
	clonePID, cloneTID := uint32(0), uint32(0)
	events := perfring.RunTestEvents(t, ctx, ops)
	for _, ev := range events {
		switch ev := ev.(type) {
		case *grpcexec.MsgExecveEventUnix:
			if ev.Unix.Process.Filename == testBin {
				execPID = ev.Unix.Process.PID
				execTID = ev.Unix.Process.TID
			}
		case *grpcexec.MsgCloneEventUnix:
			// Store all received clone events so we parse them later
			cloneEvents = append(cloneEvents, ev)
		}
	}

	tti.AssertPidsTids(t)

	require.NotZero(t, execPID)
	require.Equal(t, execPID, execTID)

	// ensure exec events match
	require.Equal(t, execPID, tti.ParentPid)
	require.Equal(t, execPID, tti.ParentChild1Pid)
	require.Equal(t, execPID, tti.ParentThread1Pid)

	for _, ev := range cloneEvents {
		// Get the clone event that orginates from the exec event
		if execPID == ev.Parent.Pid {
			clonePID = ev.PID
			cloneTID = ev.TID
		}
	}

	// ensure clone event match
	require.NotZero(t, clonePID)
	require.Equal(t, clonePID, cloneTID)
	require.Equal(t, clonePID, tti.Child1Pid)

	// ensure that threads match on the thread group leader
	require.Equal(t, tti.Child1Pid, tti.Thread1Pid)
}

func TestExecThreads(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	testBin := testutils.RepoRootPath("contrib/tester-progs/threads-tester")
	testCmd := exec.CommandContext(ctx, testBin)
	testPipes, err := testutils.NewCmdBufferedPipes(testCmd)
	if err != nil {
		t.Fatal(err)
	}
	defer testPipes.Close()

	t.Logf("starting observer")
	obs, err := observertesthelper.GetDefaultObserver(t, ctx, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	cti := &testutils.ThreadTesterInfo{}
	if err := testCmd.Start(); err != nil {
		t.Fatal(err)
	}
	logWG := testPipes.ParseAndLogCmdOutput(t, cti.ParseLine, nil)
	logWG.Wait()
	if err := testCmd.Wait(); err != nil {
		t.Fatalf("command failed with %s. Context error: %v", err, ctx.Err())
	}

	cti.AssertPidsTids(t)

	binCheck := ec.NewProcessChecker().
		WithBinary(sm.Suffix("threads-tester")).
		WithPid(cti.ParentPid).
		WithTid(cti.ParentTid)

	execCheck := ec.NewProcessExecChecker("").
		WithProcess(binCheck)

	exitCheck := ec.NewProcessExitChecker("").
		WithProcess(binCheck)

	checker := ec.NewUnorderedEventChecker(execCheck, exitCheck)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}
