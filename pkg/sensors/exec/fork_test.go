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
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/testutils"
	"github.com/stretchr/testify/assert"
)

// TestFork checks that tetragon properly handles processes that fork() but do not exec()
func TestFork(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()

	testBin := testutils.ContribPath("tester-progs/fork-tester")
	testCmd := exec.CommandContext(ctx, testBin)
	testPipes, err := testutils.NewCmdBufferedPipes(testCmd)
	if err != nil {
		t.Fatal(err)
	}
	defer testPipes.Close()

	t.Logf("starting observer")
	obs, err := observer.GetDefaultObserver(t, tetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
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

	if fti.child1Pid == 0 {
		t.Fatalf("failed to parse child1 PID")
	}
	if fti.child2Pid == 0 {
		t.Fatalf("failed to parse child1 PID")
	}

	binCheck := ec.NewProcessChecker().
		WithBinary(sm.Suffix("fork-tester")).
		WithPid(fti.child2Pid)
	exitCheck := ec.NewProcessExitChecker().
		WithProcess(binCheck).
		WithParent(ec.NewProcessChecker().WithPid(fti.child1Pid))
	checker := ec.NewUnorderedEventChecker(exitCheck)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

type forkTesterInfo struct {
	child1Pid, child2Pid uint32
}

var (
	child1Re = regexp.MustCompile(`child 1 \(pid:(\d+)\) exits`)
	// NB: ppid must be 1, to ensure that child 2 is orphan and has been inherited by init
	child2Re = regexp.MustCompile(`child 2 \(pid:(\d+), ppid:1\) connecting to 8.8.8.8:53`)
)

func (fti *forkTesterInfo) ParseLine(l string) error {
	var err error
	var v uint64
	if match := child1Re.FindStringSubmatch(l); len(match) > 0 {
		v, err = strconv.ParseUint(match[1], 10, 32)
		if err == nil {
			fti.child1Pid = uint32(v)
		}
	} else if match := child2Re.FindStringSubmatch(l); len(match) > 0 {
		v, err = strconv.ParseUint(match[1], 10, 32)
		if err == nil {
			fti.child2Pid = uint32(v)
		}
	}
	return err
}

const sampleForkTesterOutput = `
parent: (pid:118413, ppid:118401) starts
child 1 (pid:118414) exits
parent: (pid:118413, ppid:118401) starts
child 2 (pid:118415, ppid:1) connecting to 8.8.8.8:53
child 2 done
parent: (pid:118413, ppid:118401) starts
parent: (pid:118413) child (118414) exited with: 0
`

func TestForkTesterParser(t *testing.T) {
	fti := &forkTesterInfo{}
	for _, l := range strings.Split(sampleForkTesterOutput, "\n") {
		fti.ParseLine(l)
	}

	assert.Equal(t, uint32(118414), fti.child1Pid)
	assert.Equal(t, uint32(118415), fti.child2Pid)
}
