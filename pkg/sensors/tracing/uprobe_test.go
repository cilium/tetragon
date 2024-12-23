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

	"github.com/cilium/ebpf"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	lc "github.com/cilium/tetragon/pkg/matchers/listmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/testutils"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestLoadUprobeSensor(t *testing.T) {
	var sensorProgs = []tus.SensorProg{
		// uprobe
		0: tus.SensorProg{Name: "generic_uprobe_event", Type: ebpf.Kprobe},
		1: tus.SensorProg{Name: "generic_uprobe_setup_event", Type: ebpf.Kprobe},
		2: tus.SensorProg{Name: "generic_uprobe_process_event", Type: ebpf.Kprobe},
		3: tus.SensorProg{Name: "generic_uprobe_filter_arg", Type: ebpf.Kprobe},
		4: tus.SensorProg{Name: "generic_uprobe_process_filter", Type: ebpf.Kprobe},
		5: tus.SensorProg{Name: "generic_uprobe_actions", Type: ebpf.Kprobe},
		6: tus.SensorProg{Name: "generic_uprobe_output", Type: ebpf.Kprobe},
	}

	var sensorMaps = []tus.SensorMap{
		// all uprobe programs
		tus.SensorMap{Name: "process_call_heap", Progs: []uint{0, 1, 2, 3, 4, 5, 6}},

		// all but generic_uprobe_output
		tus.SensorMap{Name: "uprobe_calls", Progs: []uint{0, 1, 2, 3, 4, 5}},

		// generic_uprobe_process_filter,generic_uprobe_filter_arg*,generic_uprobe_actions
		tus.SensorMap{Name: "filter_map", Progs: []uint{3, 4, 5}},

		// generic_uprobe_output
		tus.SensorMap{Name: "tcpmon_map", Progs: []uint{6}},

		// generic_uprobe_event
		tus.SensorMap{Name: "tg_conf_map", Progs: []uint{0}},
	}

	if kernels.EnableLargeProgs() {
		// shared with base sensor
		sensorMaps = append(sensorMaps, tus.SensorMap{Name: "execve_map", Progs: []uint{4, 5, 6}})
	} else {
		// shared with base sensor
		sensorMaps = append(sensorMaps, tus.SensorMap{Name: "execve_map", Progs: []uint{4}})
	}

	nopHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe"
spec:
  uprobes:
  - path: "/bin/bash"
    symbols:
    - "main"
`

	var sens []*sensors.Sensor
	var err error

	nopConfigHook := []byte(nopHook)
	err = os.WriteFile(testConfigFile, nopConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}
	sens, err = observertesthelper.GetDefaultSensorsWithFile(t, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}

	tus.CheckSensorLoad(sens, sensorMaps, sensorProgs, t)

	sensi := make([]sensors.SensorIface, 0, len(sens))
	for _, s := range sens {
		sensi = append(sensi, s)
	}
	sensors.UnloadSensors(sensi)
}

func TestUprobeGeneric(t *testing.T) {
	testNop := testutils.RepoRootPath("contrib/tester-progs/nop")
	nopHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe"
spec:
  uprobes:
  - path: "` + testNop + `"
    symbols:
    - "main"
`

	nopConfigHook := []byte(nopHook)
	err := os.WriteFile(testConfigFile, nopConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	upChecker := ec.NewProcessUprobeChecker("UPROBE_GENERIC").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(testNop))).
		WithSymbol(sm.Full("main"))
	checker := ec.NewUnorderedEventChecker(upChecker)

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	if err := exec.Command(testNop).Run(); err != nil {
		t.Fatalf("Failed to execute test binary: %s\n", err)
	}

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func uprobePidMatch(t *testing.T, pid uint32) error {
	path, err := os.Executable()
	assert.NoError(t, err)

	pidStr := strconv.Itoa(int(pid))

	pathHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe"
spec:
  uprobes:
  - path: "` + path + `"
    symbols:
    - "uprobe_test_func"
    selectors:
    - matchPIDs:
      - operator: In
        followForks: true
        values:
        - ` + pidStr + `
`

	pathConfigHook := []byte(pathHook)
	err = os.WriteFile(testConfigFile, pathConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	upChecker := ec.NewProcessUprobeChecker("UPROBE_PID_MATCH").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(path))).
		WithSymbol(sm.Full("uprobe_test_func"))
	checker := ec.NewUnorderedEventChecker(upChecker)

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	UprobeTestFunc()

	return jsonchecker.JsonTestCheck(t, checker)
}

func TestUprobePidMatch(t *testing.T) {
	err := uprobePidMatch(t, observertesthelper.GetMyPid())
	assert.NoError(t, err)
}

func TestUprobePidMatchNot(t *testing.T) {
	err := uprobePidMatch(t, observertesthelper.GetMyPid()+1)
	assert.Error(t, err)
}

func uprobeBinariesMatch(t *testing.T, execBinary string) error {
	uprobeTest1 := testutils.RepoRootPath("contrib/tester-progs/uprobe-test-1")
	libUprobe := testutils.RepoRootPath("contrib/tester-progs/libuprobe.so")

	pathHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe"
spec:
  uprobes:
  - path: "` + libUprobe + `"
    symbols:
    - "uprobe_test_lib"
    selectors:
    - matchBinaries:
      - operator: "In"
        values:
        - "` + uprobeTest1 + `"
`

	pathConfigHook := []byte(pathHook)
	err := os.WriteFile(testConfigFile, pathConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	upChecker := ec.NewProcessUprobeChecker("UPROBE_BINARIES_MATCH").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(uprobeTest1))).
		WithSymbol(sm.Full("uprobe_test_lib"))
	checker := ec.NewUnorderedEventChecker(upChecker)

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	if err := exec.Command(execBinary).Run(); err != nil {
		t.Fatalf("Failed to execute test binary: %s\n", err)
	}

	return jsonchecker.JsonTestCheck(t, checker)
}

func TestUprobeBinariesMatch(t *testing.T) {
	uprobeTest1 := testutils.RepoRootPath("contrib/tester-progs/uprobe-test-1")
	err := uprobeBinariesMatch(t, uprobeTest1)
	assert.NoError(t, err)
}

func TestUprobeBinariesMatchNot(t *testing.T) {
	uprobeTest2 := testutils.RepoRootPath("contrib/tester-progs/uprobe-test-2")
	err := uprobeBinariesMatch(t, uprobeTest2)
	assert.Error(t, err)
}

func TestUprobeCloneThreads(t *testing.T) {
	testutils.CaptureLog(t, logger.GetLogger().(*logrus.Logger))
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	testBinPath := "contrib/tester-progs/threads-tester"
	testBin := testutils.RepoRootPath(testBinPath)

	uprobeHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe"
spec:
  uprobes:
  - path: "` + testBin + `"
    message: "Uprobe test"
    symbols:
    - "do_uprobe"
    selectors:
    - matchBinaries:
      - operator: "In"
        values:
        - "` + testBin + `"
`

	uprobeConfigHook := []byte(uprobeHook)
	err := os.WriteFile(testConfigFile, uprobeConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	testCmd := exec.CommandContext(ctx, testBin, "--sensor", "uprobe")
	testPipes, err := testutils.NewCmdBufferedPipes(testCmd)
	if err != nil {
		t.Fatal(err)
	}
	defer testPipes.Close()

	// initialize observer
	t.Logf("starting observer")
	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}

	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	cti := &testutils.ThreadTesterInfo{}
	if err := testCmd.Start(); err != nil {
		t.Fatal(err)
	}
	logWG := testPipes.ParseAndLogCmdOutput(t, cti.ParseLine, nil)
	logWG.Wait()
	if err := testCmd.Wait(); err != nil {
		t.Fatalf("command failed with %s. Context error: %v", err, ctx.Err())
	}

	cti.AssertPidsTids(t)

	parentCheck := ec.NewProcessChecker().
		WithBinary(sm.Full(testBin)).
		WithPid(cti.ParentPid).
		WithTid(cti.ParentTid)

	execCheck := ec.NewProcessExecChecker("").
		WithProcess(parentCheck)

	exitCheck := ec.NewProcessExitChecker("").
		WithProcess(parentCheck)

	child1Checker := ec.NewProcessChecker().
		WithBinary(sm.Full(testBin)).
		WithPid(cti.Child1Pid).
		WithTid(cti.Child1Tid)

	child1UpChecker := ec.NewProcessUprobeChecker("").
		WithMessage(sm.Full("Uprobe test")).
		WithSymbol(sm.Full("do_uprobe")).
		WithProcess(child1Checker).WithParent(parentCheck)

	thread1Checker := ec.NewProcessChecker().
		WithBinary(sm.Full(testBin)).
		WithPid(cti.Thread1Pid).
		WithTid(cti.Thread1Tid)

	thread1UpChecker := ec.NewProcessUprobeChecker("").
		WithMessage(sm.Full("Uprobe test")).
		WithSymbol(sm.Full("do_uprobe")).
		WithProcess(thread1Checker).WithParent(parentCheck)

	checker := ec.NewUnorderedEventChecker(execCheck, child1UpChecker, thread1UpChecker, exitCheck)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestUprobeArgs(t *testing.T) {
	execBinary := testutils.RepoRootPath("contrib/tester-progs/uprobe-test-1")
	libUprobe := testutils.RepoRootPath("contrib/tester-progs/libuprobe.so")

	pathHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe"
spec:
  uprobes:
  - path: "` + libUprobe + `"
    symbols:
    - "uprobe_test_lib_arg1"
    args:
    - index: 0
      type: "int"
    selectors:
    - matchBinaries:
      - operator: "In"
        values:
        - "` + execBinary + `"
  - path: "` + libUprobe + `"
    symbols:
    - "uprobe_test_lib_arg2"
    args:
    - index: 0
      type: "int8"
    - index: 1
      type: "int"
    selectors:
    - matchBinaries:
      - operator: "In"
        values:
        - "` + execBinary + `"
  - path: "` + libUprobe + `"
    symbols:
    - "uprobe_test_lib_arg3"
    args:
    - index: 0
      type: "uint64"
    - index: 1
      type: "uint32"
    - index: 2
      type: "uint64"
    selectors:
    - matchBinaries:
      - operator: "In"
        values:
        - "` + execBinary + `"
  - path: "` + libUprobe + `"
    symbols:
    - "uprobe_test_lib_arg4"
    args:
    - index: 0
      type: "int64"
    - index: 1
      type: "int"
    - index: 2
      type: "int8"
    - index: 3
      type: "uint64"
    selectors:
    - matchBinaries:
      - operator: "In"
        values:
        - "` + execBinary + `"
  - path: "` + libUprobe + `"
    symbols:
    - "uprobe_test_lib_arg5"
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "int8"
    - index: 2
      type: "uint64"
    - index: 3
      type: "int16"
    - index: 4
      type: "uint64"
    selectors:
    - matchBinaries:
      - operator: "In"
        values:
        - "` + execBinary + `"
`

	pathConfigHook := []byte(pathHook)
	err := os.WriteFile(testConfigFile, pathConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	check1 := ec.NewProcessUprobeChecker("UPROBE_ARG1").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(execBinary))).
		WithSymbol(sm.Full("uprobe_test_lib_arg1")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(123),
			))

	check2 := ec.NewProcessUprobeChecker("UPROBE_ARG2").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(execBinary))).
		WithSymbol(sm.Full("uprobe_test_lib_arg2")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(int32('a')),
				ec.NewKprobeArgumentChecker().WithIntArg(4321),
			))

	check3 := ec.NewProcessUprobeChecker("UPROBE_ARG3").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(execBinary))).
		WithSymbol(sm.Full("uprobe_test_lib_arg3")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithSizeArg(1),
				ec.NewKprobeArgumentChecker().WithUintArg(0xdeadbeef),
				ec.NewKprobeArgumentChecker().WithSizeArg(0),
			))

	check4 := ec.NewProcessUprobeChecker("UPROBE_ARG4").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(execBinary))).
		WithSymbol(sm.Full("uprobe_test_lib_arg4")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithLongArg(-321),
				ec.NewKprobeArgumentChecker().WithIntArg(-2),
				ec.NewKprobeArgumentChecker().WithIntArg(int32('b')),
				ec.NewKprobeArgumentChecker().WithSizeArg(1),
			))

	check5 := ec.NewProcessUprobeChecker("UPROBE_ARG5").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(execBinary))).
		WithSymbol(sm.Full("uprobe_test_lib_arg5")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(1),
				ec.NewKprobeArgumentChecker().WithIntArg(int32('c')),
				ec.NewKprobeArgumentChecker().WithSizeArg(0xcafe),
				ec.NewKprobeArgumentChecker().WithIntArg(1234),
				ec.NewKprobeArgumentChecker().WithSizeArg(2),
			))

	checker := ec.NewUnorderedEventChecker(check1, check2, check3, check4, check5)

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile,
		tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	if err := exec.Command(execBinary).Run(); err != nil {
		t.Fatalf("Failed to execute test binary: %s\n", err)
	}

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}
