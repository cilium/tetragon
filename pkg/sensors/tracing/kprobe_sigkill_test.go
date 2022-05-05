// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/pkg/eventchecker"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/testutils"
	"github.com/stretchr/testify/assert"

	_ "github.com/cilium/tetragon/pkg/sensors/exec"
)

func logOut(t *testing.T, prefix string, rd *bufio.Reader) {
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			if !errors.Is(err, io.EOF) {
				t.Logf("error reading %s: %s", prefix, err)
			}
			return
		}
		t.Logf("%s: %s", prefix, line)
	}
}

func TestKprobeSigkill(t *testing.T) {
	if !kernels.MinKernelVersion("5.3.0") {
		t.Skip("sigkill requires at least 5.3.0 version")
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()

	testBin := testutils.ContribPath("tester-progs/sigkill-tester")
	testCmd := exec.CommandContext(ctx, testBin)
	testPipes, err := testutils.NewCmdBufferedPipes(testCmd)
	if err != nil {
		t.Fatal(err)
	}

	// The first thing sigkil-tester will do is print the child PID.  So we
	// make sure to get that to use it in the spec. Next, it will print
	// messages, so we print those into the testing log.
	getPID := func() string {
		pidStr, err := testPipes.StdoutRd.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			logOut(t, "stdout> ", testPipes.StdoutRd)
		}()
		go func() {
			logOut(t, "stderr> ", testPipes.StderrRd)
		}()
		return pidStr
	}

	// makeSpecFile creates a new spec file bsed on the template, and the provided arguments
	makeSpecFile := func(pid string) string {
		data := map[string]string{
			"MatchedPID":   pid,
			"NamespacePID": "false",
		}
		specName, err := testutils.GetSpecFromTemplate("sigkill.yaml.tmpl", data)
		if err != nil {
			t.Fatal(err)
		}
		return specName
	}

	if err := testCmd.Start(); err != nil {
		t.Fatal(err)
	}

	pidStr := getPID()
	pidStr = strings.TrimSuffix(pidStr, "\n")
	specFname := makeSpecFile(pidStr)
	t.Logf("child pid is %s and spec file is %s", pidStr, specFname)

	obs, err := observer.GetDefaultObserverWithFile(t, specFname, tetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	t.Logf("waking up test program")
	testPipes.P.Stdin.Write([]byte("x"))

	if err := testCmd.Wait(); err != nil {
		t.Fatalf("command failed with %s. Context error: %s", err, ctx.Err())
	}

	kpChecker := ec.NewKprobeChecker().
		WithFunctionName("__x64_sys_lseek").
		WithArgs([]ec.GenericArgChecker{
			ec.GenericArgIntCheck(5555),
		}).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_SIGKILL)
	checker := ec.NewOrderedMultiResponseChecker(
		ec.NewKprobeEventChecker().
			HasKprobe(kpChecker).
			End(),
	)
	err = observer.JsonTestCheck(t, &checker)
	assert.NoError(t, err)
}
