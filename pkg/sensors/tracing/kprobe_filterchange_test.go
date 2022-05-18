// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"context"
	"os"
	"os/exec"
	"strconv"
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

func TestKprobeNSChanges(t *testing.T) {
	if !kernels.MinKernelVersion("5.3.0") {
		t.Skip("matchNamespaceChanges requires at least 5.3.0 version")
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()

	testBin := testContribPath("tester-progs/namespace-tester")
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
			"MatchedPID":   pid,
			"NamespacePID": "false",
		}
		specName, err := testutils.GetSpecFromTemplate("nschanges.yaml.tmpl", data)
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

	writeArg0 = ec.GenericArgFileChecker(ec.StringMatchAlways(), ec.SuffixStringMatch("strange.txt"), ec.FullStringMatch(""))
	writeArg1 = ec.GenericArgBytesCheck([]byte("testdata\x00"))
	writeArg2 = ec.GenericArgSizeCheck(9)
	kpChecker := ec.NewKprobeChecker().
		WithFunctionName("__x64_sys_write").
		WithArgs([]ec.GenericArgChecker{writeArg0, writeArg1, writeArg2}).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_POST)
	checker := ec.NewOrderedMultiResponseChecker(
		ec.NewKprobeEventChecker().
			HasKprobe(kpChecker).
			HasKprobe(kpChecker).
			End(),
	)
	err = observer.JsonTestCheck(t, &checker)
	assert.NoError(t, err)
}

func TestKprobeCapChanges(t *testing.T) {
	if !kernels.MinKernelVersion("5.3.0") {
		t.Skip("matchCapabilityChanges requires at least 5.3.0 version")
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()

	testBin := testContribPath("tester-progs/capabilities-tester")
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
			"MatchedPID":   pid,
			"NamespacePID": "false",
		}
		specName, err := testutils.GetSpecFromTemplate("capchanges.yaml.tmpl", data)
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

	writeArg0 = ec.GenericArgFileChecker(ec.StringMatchAlways(), ec.SuffixStringMatch("strange.txt"), ec.FullStringMatch(""))
	writeArg1 = ec.GenericArgBytesCheck([]byte("testdata\x00"))
	writeArg2 = ec.GenericArgSizeCheck(9)
	kpChecker := ec.NewKprobeChecker().
		WithFunctionName("__x64_sys_write").
		WithArgs([]ec.GenericArgChecker{writeArg0, writeArg1, writeArg2}).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_POST)
	checker := ec.NewOrderedMultiResponseChecker(
		ec.NewKprobeEventChecker().
			HasKprobe(kpChecker).
			HasKprobe(kpChecker).
			End(),
	)
	err = observer.JsonTestCheck(t, &checker)
	assert.NoError(t, err)
}
