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
	"github.com/stretchr/testify/require"
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

	if fti.parentPID == 0 {
		t.Fatalf("failed to parse parent PID")
	}
	if fti.child1PID == 0 {
		t.Fatalf("failed to parse child1 PID")
	}
	if fti.child2PID == 0 {
		t.Fatalf("failed to parse child2 PID")
	}
	if fti.child2ExitPPID == 0 {
		t.Fatalf("failed to parse child2 PPID")
	}

	binCheck := ec.NewProcessChecker().
		WithBinary(sm.Suffix("fork-tester")).
		WithPid(fti.child2PID)
	exitCheck := ec.NewProcessExitChecker("").
		WithProcess(binCheck).
		WithParent(ec.NewProcessChecker().WithPid(fti.child1PID))
	checker := ec.NewUnorderedEventChecker(exitCheck)

	err = jsonchecker.JSONTestCheck(t, checker)
	require.NoError(t, err)
}

type forkTesterInfo struct {
	parentPID, child1PID, child2PID, child2ExitPPID uint32
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
			fti.parentPID = uint32(v)
		}
	} else if match := child1Re.FindStringSubmatch(l); len(match) > 0 {
		v, err = strconv.ParseUint(match[1], 10, 32)
		if err == nil {
			fti.child1PID = uint32(v)
		}
	} else if match := child2Re.FindStringSubmatch(l); len(match) > 0 {
		v, err = strconv.ParseUint(match[1], 10, 32)
		if err == nil {
			fti.child2PID = uint32(v)
		}
		ppid, err := strconv.ParseUint(match[2], 10, 32)
		if err == nil {
			fti.child2ExitPPID = uint32(ppid)
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

	assert.Equal(t, uint32(118413), fti.parentPID)
	assert.Equal(t, uint32(118414), fti.child1PID)
	assert.Equal(t, uint32(118415), fti.child2PID)
	assert.Equal(t, fti.parentPID, fti.child2ExitPPID)
}
