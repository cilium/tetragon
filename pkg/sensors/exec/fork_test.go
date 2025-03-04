// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package exec

import (
	"context"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/testutils"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/stretchr/testify/assert"
)

// TestFork checks that tetragon properly handles processes that fork() but do not exec()
func TestFork(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	testBin := testutils.RepoRootPath("contrib/tester-progs/fork-tester")
	testCmd := exec.CommandContext(ctx, testBin)
	testPipes, err := testutils.NewCmdBufferedPipes(testCmd)
	if err != nil {
		t.Fatal(err)
	}
	defer testPipes.Close()

	t.Logf("starting observer")
	obs, err := observertesthelper.GetDefaultObserver(t, ctx, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	fti := &forkTesterInfo{}
	if err := testCmd.Start(); err != nil {
		t.Fatal(err)
	}
	logWG := testPipes.ParseAndLogCmdOutput(t, fti.ParseLine, nil)
	logWG.Wait()
	if err := testCmd.Wait(); err != nil {
		t.Fatalf("command failed with %s. Context error: %v", err, ctx.Err())
	}

	if fti.parentPid == 0 {
		t.Fatalf("failed to parse parent PID")
	}
	if fti.child1Pid == 0 {
		t.Fatalf("failed to parse child1 PID")
	}
	if fti.child2Pid == 0 {
		t.Fatalf("failed to parse child2 PID")
	}
	if fti.child2ExitPpid == 0 {
		t.Fatalf("failed to parse child2 PPID")
	}

	binCheck := ec.NewProcessChecker().
		WithBinary(sm.Suffix("fork-tester")).
		WithPid(fti.child2Pid)
	exitCheck := ec.NewProcessExitChecker("").
		WithProcess(binCheck).
		WithParent(ec.NewProcessChecker().WithPid(fti.child1Pid))
	checker := ec.NewUnorderedEventChecker(exitCheck)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

type forkTesterInfo struct {
	parentPid, child1Pid, child2Pid, child2ExitPpid uint32
}

var (
	parentRe = regexp.MustCompile(`parent \(pid:(\d+)\, ppid:(\d+)\) starts`)
	child1Re = regexp.MustCompile(`child 1 \(pid:(\d+)\) exits`)
	child2Re = regexp.MustCompile(`child 2 \(pid:(\d+), ppid:(\d+)\) exits`)
)

func (fti *forkTesterInfo) ParseLine(l string) error {
	var err error
	var v uint64
	if match := parentRe.FindStringSubmatch(l); len(match) > 0 {
		v, err = strconv.ParseUint(match[1], 10, 32)

		if err == nil {
			fti.parentPid = uint32(v)
		}
	} else if match := child1Re.FindStringSubmatch(l); len(match) > 0 {
		v, err = strconv.ParseUint(match[1], 10, 32)
		if err == nil {
			fti.child1Pid = uint32(v)
		}
	} else if match := child2Re.FindStringSubmatch(l); len(match) > 0 {
		v, err = strconv.ParseUint(match[1], 10, 32)
		if err == nil {
			fti.child2Pid = uint32(v)
		}
		ppid, err := strconv.ParseUint(match[2], 10, 32)
		if err == nil {
			fti.child2ExitPpid = uint32(ppid)
		}
	}
	return err
}

const sampleForkTesterOutput = `
parent (pid:118413, ppid:118401) starts
child 1 (pid:118414) exits
child 2 (pid:118415, ppid:118414) starts
parent (pid:118413) child (118414) exited with: 0
child 2 (pid:118415, ppid:118413) exits
parent (pid:118413) child (118415) exited with: 0
parent (pid:118413) no more descendants
`

func TestForkTesterParser(t *testing.T) {
	fti := &forkTesterInfo{}
	for _, l := range strings.Split(sampleForkTesterOutput, "\n") {
		fti.ParseLine(l)
	}

	assert.Equal(t, uint32(118413), fti.parentPid)
	assert.Equal(t, uint32(118414), fti.child1Pid)
	assert.Equal(t, uint32(118415), fti.child2Pid)
	assert.Equal(t, fti.parentPid, fti.child2ExitPpid)
}
