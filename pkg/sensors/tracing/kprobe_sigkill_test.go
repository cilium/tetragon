// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"context"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/arch"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/kernels"
	lc "github.com/cilium/tetragon/pkg/matchers/listmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	smatcher "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/testutils"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/stretchr/testify/assert"

	_ "github.com/cilium/tetragon/pkg/sensors/exec"
)

func testSigkill(t *testing.T, makeSpecFile func(pid string) string, checker *eventchecker.UnorderedEventChecker) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	testBin := testutils.RepoRootPath("contrib/tester-progs/sigkill-tester")
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

	if err := testCmd.Start(); err != nil {
		t.Fatal(err)
	}

	pidStr := getPID()
	pidStr = strings.TrimSuffix(pidStr, "\n")
	specFname := makeSpecFile(pidStr)
	t.Logf("child pid is %s and spec file is %s", pidStr, specFname)

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, specFname, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	t.Logf("waking up test program")
	testPipes.P.Stdin.Write([]byte("x"))

	logWG := testPipes.ParseAndLogCmdOutput(t, nil, nil)
	logWG.Wait()

	if err := testCmd.Wait(); err != nil {
		t.Fatalf("command failed with %s. Context error: %s", err, ctx.Err())
	}

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestKprobeSigkill(t *testing.T) {
	if !kernels.MinKernelVersion("5.3.0") {
		t.Skip("sigkill requires at least 5.3.0 version")
	}

	// makeSpecFile creates a new spec file based on the template, and the provided arguments
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

	kpChecker := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full(arch.AddSyscallPrefixTestHelper(t, "sys_lseek"))).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(5555),
			)).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_SIGKILL)
	checker := ec.NewUnorderedEventChecker(kpChecker)

	testSigkill(t, makeSpecFile, checker)
}

func TestKprobeSigkillExecveMap1(t *testing.T) {
	if !kernels.MinKernelVersion("5.3.0") {
		t.Skip("sigkill requires at least 5.3.0 version")
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

	kpChecker := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full(arch.AddSyscallPrefixTestHelper(t, "sys_lseek"))).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(5555),
			)).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_SIGKILL).
		WithProcess(ec.NewProcessChecker().WithFlags(sm.Full("unknown")))

	checker := ec.NewUnorderedEventChecker(kpChecker)

	option.Config.ExecveMapEntries = 1
	testSigkill(t, makeSpecFile, checker)
	option.Config.ExecveMapEntries = 0
}

func TestTracepointSigkillExecveMap1(t *testing.T) {
	if !kernels.MinKernelVersion("5.3.0") {
		t.Skip("sigkill requires at least 5.3.0 version")
	}

	// makeSpecFile creates a new spec file bsed on the template, and the provided arguments
	makeSpecFile := func(pid string) string {
		data := map[string]string{
			"MatchedPID":   pid,
			"NamespacePID": "false",
		}
		specName, err := testutils.GetSpecFromTemplate("sigkill_tracepoint.yaml.tmpl", data)
		if err != nil {
			t.Fatal(err)
		}
		return specName
	}

	kpChecker := ec.NewProcessTracepointChecker("").
		WithSubsys(smatcher.Full("syscalls")).
		WithEvent(smatcher.Full("sys_enter_lseek")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(int32(5555)),
			)).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_SIGKILL).
		WithProcess(ec.NewProcessChecker().WithFlags(sm.Full("unknown")))

	checker := ec.NewUnorderedEventChecker(kpChecker)

	option.Config.ExecveMapEntries = 1
	testSigkill(t, makeSpecFile, checker)
	option.Config.ExecveMapEntries = 0
}

func TestReturnKprobeSigkill(t *testing.T) {
	if !kernels.MinKernelVersion("5.3.0") {
		t.Skip("sigkill requires at least 5.3.0 version")
	}

	// makeSpecFile creates a new spec file bsed on the template, and the provided arguments
	makeSpecFile := func(pid string) string {
		data := map[string]string{
			"MatchedPID":   pid,
			"NamespacePID": "false",
		}
		specName, err := testutils.GetSpecFromTemplate("sigkill_return.yaml.tmpl", data)
		if err != nil {
			t.Fatal(err)
		}
		return specName
	}

	kpChecker := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full(arch.AddSyscallPrefixTestHelper(t, "sys_lseek"))).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(5555),
			)).
		WithReturn(ec.NewKprobeArgumentChecker().WithIntArg(-9)).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_POST).
		WithReturnAction(tetragon.KprobeAction_KPROBE_ACTION_SIGKILL)
	checker := ec.NewUnorderedEventChecker(kpChecker)

	testSigkill(t, makeSpecFile, checker)
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
	testBin := testutils.RepoRootPath("contrib/tester-progs/sigkill-unprivileged-user-ns-tester")
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

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, specFname, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	t.Logf("waking up test program")
	testPipes.P.Stdin.Write([]byte("x"))

	logWG := testPipes.ParseAndLogCmdOutput(t, nil, nil)
	logWG.Wait()

	if err := testCmd.Wait(); err != nil {
		t.Fatalf("command failed with %s. Context error: %s", err, ctx.Err())
	}

	kpChecker := ec.NewProcessKprobeChecker("").
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
