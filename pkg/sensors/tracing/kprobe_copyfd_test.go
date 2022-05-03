//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package tracing

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"testing"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/pkg/eventchecker"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/testutils"
	"github.com/stretchr/testify/assert"

	_ "github.com/cilium/tetragon/pkg/sensors/exec"
)

func TestCopyFd(t *testing.T) {
	kataRun := false
	if os.Getenv("FGS_KATA_RUNNER") == "1" {
		t.Log("running inside kata...")
		kataRun = true
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()

	testBin := testutils.ContribPath("tester-progs/dup-tester")
	testCmd := exec.CommandContext(ctx, testBin)
	testPipes, err := testutils.NewCmdBufferedPipes(testCmd)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		logOut(t, "stdout> ", testPipes.StdoutRd)
	}()

	go func() {
		logOut(t, "stderr> ", testPipes.StderrRd)
	}()

	// makeSpecFile creates a new spec file bsed on the template, and the provided arguments
	makeSpecFile := func(pid string) string {
		data := map[string]string{
			"MatchedPID": pid,
			// NB: if this is a kata run, the pid that the ns-tester will print,
			// will be inside the namespace.
			"NamespacePID": fmt.Sprintf("%t", kataRun),
		}
		specName, err := testutils.GetSpecFromTemplate("copyfd.yaml.tmpl", data)
		if err != nil {
			t.Fatal(err)
		}
		return specName
	}

	pidStr := strconv.Itoa(os.Getpid())
	specFname := makeSpecFile(pidStr)
	t.Logf("pid is %s and spec file is %s", pidStr, specFname)

	obs, err := observer.GetDefaultObserverWithFile(t, specFname, tetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	if err := testCmd.Start(); err != nil {
		t.Fatal(err)
	}

	if err := testCmd.Wait(); err != nil {
		t.Fatalf("command failed with %s. Context error: %s", err, ctx.Err())
	}

	readArg0 := ec.GenericArgFileChecker(ec.StringMatchAlways(), ec.SuffixStringMatch("strange.txt"), ec.FullStringMatch(""))
	readArg1 := ec.GenericArgBytesCheck([]byte("testdata\x00"))
	readArg2 := ec.GenericArgSizeCheck(9)
	kpChecker := ec.NewKprobeChecker().
		WithFunctionName("__x64_sys_read").
		WithArgs([]ec.GenericArgChecker{readArg0, readArg1, readArg2}).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_POST)
	checker := ec.NewOrderedMultiResponseChecker(
		ec.NewKprobeEventChecker().
			HasKprobe(kpChecker).
			HasKprobe(kpChecker).
			HasKprobe(kpChecker).
			HasKprobe(kpChecker).
			End(),
	)
	err = observer.JsonTestCheck(t, &checker)
	assert.NoError(t, err)
}
