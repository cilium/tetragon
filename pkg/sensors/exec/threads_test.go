package exec

import (
	"context"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/testutils"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/stretchr/testify/assert"
)

type cloneTesterInfo struct {
	parentPid, parentTid                     uint32
	child1Pid, child1Tid, parentChild1Pid    uint32
	thread1Pid, thread1Tid, parentThread1Pid uint32
}

var (
	parentRe       = regexp.MustCompile(`parent:\t\t\(pid:(\d+), tid:(\d+), ppid:(\d+)\)\tstarts`)
	cloneChild1Re  = regexp.MustCompile(`Child 1:\t\(pid:(\d+), tid:(\d+), ppid:(\d+)\)\topen`)
	cloneThread1Re = regexp.MustCompile(`Thread 1:\t\(pid:(\d+), tid:(\d+), ppid:(\d+)\)\topen`)
)

func (cti *cloneTesterInfo) ParseLine(l string) error {
	var err error
	var v uint64
	if match := parentRe.FindStringSubmatch(l); len(match) > 0 {
		v, err = strconv.ParseUint(match[1], 10, 32)
		if err == nil {
			cti.parentPid = uint32(v)
		}
		v, err = strconv.ParseUint(match[2], 10, 32)
		if err == nil {
			cti.parentTid = uint32(v)
		}
	} else if match := cloneChild1Re.FindStringSubmatch(l); len(match) > 0 {
		v, err = strconv.ParseUint(match[1], 10, 32)
		if err == nil {
			cti.child1Pid = uint32(v)
		}
		v, err = strconv.ParseUint(match[2], 10, 32)
		if err == nil {
			cti.child1Tid = uint32(v)
		}
		v, err = strconv.ParseUint(match[3], 10, 32)
		if err == nil {
			cti.parentChild1Pid = uint32(v)
		}
	} else if match := cloneThread1Re.FindStringSubmatch(l); len(match) > 0 {
		v, err = strconv.ParseUint(match[1], 10, 32)
		if err == nil {
			cti.thread1Pid = uint32(v)
		}
		v, err = strconv.ParseUint(match[2], 10, 32)
		if err == nil {
			cti.thread1Tid = uint32(v)
		}
		v, err = strconv.ParseUint(match[3], 10, 32)
		if err == nil {
			cti.parentThread1Pid = uint32(v)
		}
	}
	return err
}

const sampleCloneTesterOutput = `
parent:		(pid:143563, tid:143563, ppid:7860)	starts
Thread 1:	(pid:143564, tid:143565, ppid:143563)	open("/etc/issue") succeeded
Child 1:	(pid:143564, tid:143564, ppid:143563)	open("/etc/issue") succeeded
parent:		(pid:143563, tid:143563, ppid:7860)	child1 (143564) exited with: 0
`

func TestCloneTesterParser(t *testing.T) {
	cti := &cloneTesterInfo{}
	for _, l := range strings.Split(sampleCloneTesterOutput, "\n") {
		cti.ParseLine(l)
	}

	assert.Equal(t, uint32(143563), cti.parentPid)
	assert.Equal(t, cti.parentPid, cti.parentTid)
	assert.Equal(t, uint32(143564), cti.child1Pid)
	assert.Equal(t, cti.child1Pid, cti.child1Tid)
	assert.Equal(t, cti.parentPid, cti.parentChild1Pid)
	assert.Equal(t, uint32(143564), cti.thread1Pid)
	assert.Equal(t, uint32(143565), cti.thread1Tid)
	assert.Equal(t, cti.parentPid, cti.parentThread1Pid)
}

func TestExecThreads(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	testBin := testutils.RepoRootPath("contrib/tester-progs/clone-threads-tester")
	testCmd := exec.CommandContext(ctx, testBin)
	testPipes, err := testutils.NewCmdBufferedPipes(testCmd)
	if err != nil {
		t.Fatal(err)
	}
	defer testPipes.Close()

	t.Logf("starting observer")
	obs, err := observer.GetDefaultObserver(t, ctx, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	cti := &cloneTesterInfo{}
	if err := testCmd.Start(); err != nil {
		t.Fatal(err)
	}
	logWG := testPipes.ParseAndLogCmdOutput(t, cti.ParseLine, nil)
	logWG.Wait()
	if err := testCmd.Wait(); err != nil {
		t.Fatalf("command failed with %s. Context error: %v", err, ctx.Err())
	}

	require.NotZero(t, cti.child1Pid)
	require.NotZero(t, cti.child1Tid)
	require.Equal(t, cti.child1Pid, cti.child1Tid)

	require.NotZero(t, cti.thread1Pid)
	require.NotZero(t, cti.thread1Tid)
	require.NotEqual(t, cti.thread1Pid, cti.thread1Tid)

	require.Equal(t, cti.child1Pid, cti.thread1Pid)
	require.Equal(t, cti.parentChild1Pid, cti.parentPid)
	require.Equal(t, cti.parentThread1Pid, cti.parentPid)

	binCheck := ec.NewProcessChecker().
		WithBinary(sm.Suffix("clone-threads-tester")).
		WithPid(cti.parentPid).
		WithTid(cti.parentTid)

	execCheck := ec.NewProcessExecChecker("").
		WithProcess(binCheck)

	exitCheck := ec.NewProcessExitChecker("").
		WithProcess(binCheck)

	checker := ec.NewUnorderedEventChecker(execCheck, exitCheck)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}
