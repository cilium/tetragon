// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"context"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/kernels"
	lc "github.com/cilium/tetragon/pkg/matchers/listmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/testutils"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/stretchr/testify/assert"

	_ "github.com/cilium/tetragon/pkg/sensors/exec"
)

func TestKprobeSigkill(t *testing.T) {
	if !kernels.MinKernelVersion("5.3.0") {
		t.Skip("sigkill requires at least 5.3.0 version")
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	testBin := testutils.ContribPath("tester-progs/sigkill-tester")
	testCmd := exec.CommandContext(ctx, testBin)
	testPipes, err := testutils.NewCmdBufferedPipes(testCmd)
	if err != nil {
		t.Fatal(err)
	}
	defer testPipes.Close()

	// The first thing sigkil-tester will do is print the child PID.  So we
	// make sure to get that to use it in the spec. Next, it will print
	// messages, so we print those into the testing log.
	getPID := func() string {
		pidStr, err := testPipes.StdoutRd.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
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

	obs, err := observer.GetDefaultObserverWithFile(t, ctx, specFname, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	t.Logf("waking up test program")
	testPipes.P.Stdin.Write([]byte("x"))

	logWG := testPipes.ParseAndLogCmdOutput(t, nil, nil)
	logWG.Wait()

	if err := testCmd.Wait(); err != nil {
		t.Fatalf("command failed with %s. Context error: %s", err, ctx.Err())
	}

	kpChecker := ec.NewProcessKprobeChecker().
		WithFunctionName(sm.Full("__x64_sys_lseek")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(5555),
			)).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_SIGKILL)
	checker := ec.NewUnorderedEventChecker(kpChecker)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func testUnprivilegedUsernsKill(t *testing.T, pidns bool) {
	if !kernels.MinKernelVersion("5.3.0") {
		t.Skip("sigkill requires at least 5.3.0 version")
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	specFile := ""
	var testCmd *exec.Cmd
	testBin := testutils.ContribPath("tester-progs/sigkill-unprivileged-user-ns-tester")
	if pidns {
		specFile = "sigkill_unprivileged_user_namespace_in_pid_namespace.yaml.tmpl"
		testCmd = exec.CommandContext(ctx, testBin, "pidns")
	} else {
		specFile = "sigkill_unprivileged_user_namespace.yaml.tmpl"
		testCmd = exec.CommandContext(ctx, testBin)
	}

	testPipes, err := testutils.NewCmdBufferedPipes(testCmd)
	if err != nil {
		t.Fatal(err)
	}
	defer testPipes.Close()

	getPID := func() string {
		pidStr, err := testPipes.StdoutRd.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		return pidStr
	}

	// makeSpecFile creates a new spec file bsed on the template, and the provided arguments
	makeSpecFile := func(pid string) string {
		data := map[string]string{
			"MatchedPID": pid,
		}
		specName, err := testutils.GetSpecFromTemplate(specFile, data)
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
	t.Logf("parent pid is %s and spec file is %s", pidStr, specFname)

	obs, err := observer.GetDefaultObserverWithFile(t, ctx, specFname, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	t.Logf("waking up test program")
	testPipes.P.Stdin.Write([]byte("x"))

	logWG := testPipes.ParseAndLogCmdOutput(t, nil, nil)
	logWG.Wait()

	if err := testCmd.Wait(); err != nil {
		t.Fatalf("command failed with %s. Context error: %s", err, ctx.Err())
	}

	kpChecker := ec.NewProcessKprobeChecker().
		WithFunctionName(sm.Full("create_user_ns")).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_SIGKILL)

	checker := ec.NewUnorderedEventChecker(kpChecker)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestKillUnprivilegedUserns(t *testing.T) {
	testUnprivilegedUsernsKill(t, false)
}

func TestKillUnprivilegedUsernsPidns(t *testing.T) {
	testUnprivilegedUsernsKill(t, true)
}

func TestKillRawIOSyscallsGroupPidns(t *testing.T) {
	if !kernels.MinKernelVersion("5.3.0") {
		t.Skip("sigkill requires at least 5.3.0 version")
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	specFile := "sigkill_rawio_syscalls_group_in_pid_namespace.yaml.tmpl"
	testBin := testutils.ContribPath("tester-progs/sigkill-rawio-syscalls-group-tester")
	testCmd := exec.CommandContext(ctx, testBin)

	testPipes, err := testutils.NewCmdBufferedPipes(testCmd)
	if err != nil {
		t.Fatal(err)
	}
	defer testPipes.Close()

	getPID := func() string {
		pidStr, err := testPipes.StdoutRd.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		return pidStr
	}

	// makeSpecFile creates a new spec file bsed on the template, and the provided arguments
	makeSpecFile := func(pid string) string {
		data := map[string]string{
			"MatchedPID": pid,
		}
		specName, err := testutils.GetSpecFromTemplate(specFile, data)
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
	t.Logf("parent pid is %s and spec file is %s", pidStr, specFname)

	obs, err := observer.GetDefaultObserverWithFile(t, ctx, specFname, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	t.Logf("waking up test program")
	testPipes.P.Stdin.Write([]byte("x"))

	logWG := testPipes.ParseAndLogCmdOutput(t, nil, nil)
	logWG.Wait()

	if err := testCmd.Wait(); err != nil {
		t.Fatalf("command failed with %s. Context error: %s", err, ctx.Err())
	}

	kpChecker := ec.NewProcessKprobeChecker().
		WithFunctionName(sm.Full("__x64_sys_ioperm")).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_SIGKILL)

	checker := ec.NewUnorderedEventChecker(kpChecker)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestKillModuleSyscallsGroupPidns(t *testing.T) {
	if !kernels.MinKernelVersion("5.3.0") {
		t.Skip("sigkill requires at least 5.3.0 version")
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	specFile := "sigkill_module_syscalls_group_in_pid_namespace.yaml.tmpl"
	testBin := testutils.ContribPath("tester-progs/sigkill-module-syscalls-group-tester")
	testPath := testutils.ContribPath("tester-progs")
	testCmd := exec.CommandContext(ctx, testBin, testPath, "kernel_module_hello")

	testPipes, err := testutils.NewCmdBufferedPipes(testCmd)
	if err != nil {
		t.Fatal(err)
	}
	defer testPipes.Close()

	getPID := func() string {
		pidStr, err := testPipes.StdoutRd.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		return pidStr
	}

	// makeSpecFile creates a new spec file bsed on the template, and the provided arguments
	makeSpecFile := func(pid string) string {
		data := map[string]string{
			"MatchedPID": pid,
		}
		specName, err := testutils.GetSpecFromTemplate(specFile, data)
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
	t.Logf("parent pid is %s and spec file is %s", pidStr, specFname)

	obs, err := observer.GetDefaultObserverWithFile(t, ctx, specFname, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	t.Logf("waking up test program")
	testPipes.P.Stdin.Write([]byte("x"))

	logWG := testPipes.ParseAndLogCmdOutput(t, nil, nil)
	logWG.Wait()

	if err := testCmd.Wait(); err != nil {
		t.Fatalf("command failed with %s. Context error: %s", err, ctx.Err())
	}

	kpChecker := ec.NewProcessKprobeChecker().
		WithFunctionName(sm.Full("__x64_sys_finit_module")).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_SIGKILL)

	checker := ec.NewUnorderedEventChecker(kpChecker)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}
