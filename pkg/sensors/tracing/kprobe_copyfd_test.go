// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"testing"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/arch"
	"github.com/cilium/tetragon/pkg/ftrace"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/kernels"
	bc "github.com/cilium/tetragon/pkg/matchers/bytesmatcher"
	lc "github.com/cilium/tetragon/pkg/matchers/listmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/testutils"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/stretchr/testify/assert"

	_ "github.com/cilium/tetragon/pkg/sensors/exec"
)

func TestCopyFd(t *testing.T) {
	if !kernels.MinKernelVersion("5.3.0") {
		t.Skip("TestCopyFd requires at least 5.3.0 version")
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	testBin := testutils.RepoRootPath("contrib/tester-progs/dup-tester")
	testCmd := exec.CommandContext(ctx, testBin)
	testPipes, err := testutils.NewCmdBufferedPipes(testCmd)
	if err != nil {
		t.Fatal(err)
	}
	defer testPipes.Close()

	// makeSpecFile creates a new spec file bsed on the template, and the provided arguments
	makeSpecFile := func(pid string) string {
		data := map[string]string{
			"MatchedPID": pid,
		}
		// For kernels <= 5.10, dup syscall calls fd_install, which calls
		// __fd_install. fd_install is inlined and if we hook there we miss
		// the dup event. For kernels > 5.10 __fd_install is removed.
		templatePath := "copyfd-fd_install.yaml.tmpl"
		if _, err := ftrace.ReadAvailFuncs("^__fd_install$"); err == nil {
			templatePath = "copyfd-__fd_install.yaml.tmpl"
		}
		specName, err := testutils.GetSpecFromTemplate(templatePath, data)
		if err != nil {
			t.Fatal(err)
		}
		return specName
	}

	pidStr := strconv.Itoa(os.Getpid())
	specFname := makeSpecFile(pidStr)
	t.Logf("pid is %s and spec file is %s", pidStr, specFname)

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, specFname, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	if err := testCmd.Start(); err != nil {
		t.Fatal(err)
	}

	logWG := testPipes.ParseAndLogCmdOutput(t, nil, nil)
	logWG.Wait()

	if err := testCmd.Wait(); err != nil {
		t.Fatalf("command failed with %s. Context error: %s", err, ctx.Err())
	}

	kpChecker := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full(arch.AddSyscallPrefixTestHelper(t, "sys_read"))).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithFileArg(ec.NewKprobeFileChecker().WithPath(sm.Suffix("strange.txt"))),
				ec.NewKprobeArgumentChecker().WithBytesArg(bc.Full([]byte("testdata\x00"))),
				ec.NewKprobeArgumentChecker().WithSizeArg(9),
			)).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_POST)
	checker := ec.NewUnorderedEventChecker(
		kpChecker,
		kpChecker,
		kpChecker,
		kpChecker,
	)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}
