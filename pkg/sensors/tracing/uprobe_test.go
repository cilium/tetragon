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
	"github.com/stretchr/testify/require"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	bc "github.com/cilium/tetragon/pkg/matchers/bytesmatcher"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/elf"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	lc "github.com/cilium/tetragon/pkg/matchers/listmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/testutils"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

func TestLoadUprobeSensor(t *testing.T) {
	var (
		sensorProgs []tus.SensorProg
		sensorMaps  []tus.SensorMap
	)

	if config.EnableV61Progs() {
		sensorProgs = []tus.SensorProg{
			// uprobe
			0: {Name: "generic_uprobe_event", Type: ebpf.Kprobe},
			1: {Name: "generic_uprobe_setup_event", Type: ebpf.Kprobe},
			2: {Name: "generic_uprobe_process_event", Type: ebpf.Kprobe},
			3: {Name: "generic_uprobe_filter_arg", Type: ebpf.Kprobe},
			4: {Name: "generic_uprobe_process_filter", Type: ebpf.Kprobe},
			5: {Name: "generic_uprobe_actions", Type: ebpf.Kprobe},
			6: {Name: "generic_uprobe_output", Type: ebpf.Kprobe},
		}

		sensorMaps = []tus.SensorMap{
			// all uprobe programs
			{Name: "process_call_heap", Progs: []uint{0, 1, 2, 3, 4, 5, 6}},

			// all but generic_uprobe_output
			{Name: "uprobe_calls", Progs: []uint{0, 1, 2, 3, 4, 5}},

			// generic_uprobe_process_filter,generic_uprobe_filter_arg*,generic_uprobe_actions
			{Name: "filter_map", Progs: []uint{3, 4, 5}},

			// generic_uprobe_output
			{Name: "tcpmon_map", Progs: []uint{6}},
			{Name: "tg_rb_events", Progs: []uint{6}},

			// generic_uprobe_event
			{Name: "tg_conf_map", Progs: []uint{0, 6}},

			// shared with base sensor
			{Name: "execve_map", Progs: []uint{4, 5, 6}},
		}
	} else {
		sensorProgs = []tus.SensorProg{
			// uprobe
			0: {Name: "generic_uprobe_event", Type: ebpf.Kprobe},
			1: {Name: "generic_uprobe_setup_event", Type: ebpf.Kprobe},
			2: {Name: "generic_uprobe_process_event", Type: ebpf.Kprobe},
			3: {Name: "generic_uprobe_filter_arg", Type: ebpf.Kprobe},
			4: {Name: "generic_uprobe_process_filter", Type: ebpf.Kprobe},
			5: {Name: "generic_uprobe_actions", Type: ebpf.Kprobe},
			6: {Name: "generic_uprobe_output", Type: ebpf.Kprobe},
			7: {Name: "generic_uprobe_path", Type: ebpf.Kprobe},
		}

		sensorMaps = []tus.SensorMap{
			// all uprobe programs
			{Name: "process_call_heap", Progs: []uint{0, 1, 2, 3, 4, 5, 6, 7}},

			// all but generic_uprobe_output
			{Name: "uprobe_calls", Progs: []uint{0, 1, 2, 3, 4, 5, 7}},

			// generic_uprobe_process_filter,generic_uprobe_filter_arg*,generic_uprobe_actions
			{Name: "filter_map", Progs: []uint{3, 4, 5}},

			// generic_uprobe_output
			{Name: "tcpmon_map", Progs: []uint{6}},
		}

		if config.EnableLargeProgs() {
			// shared with base sensor
			sensorMaps = append(sensorMaps, tus.SensorMap{Name: "execve_map", Progs: []uint{4, 5, 6}})

			if config.EnableV511Progs() {
				sensorMaps = append(sensorMaps, tus.SensorMap{Name: "tg_conf_map", Progs: []uint{0, 6}})
				sensorMaps = append(sensorMaps, tus.SensorMap{Name: "tg_rb_events", Progs: []uint{6}})
			} else {
				sensorMaps = append(sensorMaps, tus.SensorMap{Name: "tg_conf_map", Progs: []uint{0}})
			}
		} else {
			// shared with base sensor
			sensorMaps = append(sensorMaps, tus.SensorMap{Name: "execve_map", Progs: []uint{4}})
			sensorMaps = append(sensorMaps, tus.SensorMap{Name: "tg_conf_map", Progs: []uint{0}})
		}
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
	require.NoError(t, err)
}

func TestUretprobeGeneric(t *testing.T) {
	testUretprobe := testutils.RepoRootPath("contrib/tester-progs/uretprobe")
	uretprobeHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: uretprobe
spec:
  uprobes:
  - path: "` + testUretprobe + `"
    symbols:
    - "return_string"
    return: true
    returnArg:
      index: 0
      type: "string"
`

	uretprobeConfigHook := []byte(uretprobeHook)
	err := os.WriteFile(testConfigFile, uretprobeConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	upChecker := ec.NewProcessUprobeChecker("URETPROBE_GENERIC").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(testUretprobe))).
		WithSymbol(sm.Full("return_string")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithStringArg(sm.Full("ret input")),
			))
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

	err = exec.Command(testUretprobe).Run()
	require.NoError(t, err)

	err = jsonchecker.JsonTestCheck(t, checker)
	require.NoError(t, err)
}

func TestUretprobeRetCopy(t *testing.T) {
	testUretprobe := testutils.RepoRootPath("contrib/tester-progs/uretprobe")
	uretprobeHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: uretprobe
spec:
  uprobes:
  - path: "` + testUretprobe + `"
    symbols:
    - "fill_string"
    args:
    - index: 0
      type: "char_buf"
      returnCopy: true
`

	uretprobeConfigHook := []byte(uretprobeHook)
	err := os.WriteFile(testConfigFile, uretprobeConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	upChecker := ec.NewProcessUprobeChecker("URETPROBE_RETCOPY").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(testUretprobe))).
		WithSymbol(sm.Full("fill_string")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithBytesArg(bc.Full([]byte("filled\000"))),
			))
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

	err = exec.Command(testUretprobe).Run()
	require.NoError(t, err)

	err = jsonchecker.JsonTestCheck(t, checker)
	require.NoError(t, err)
}

func uprobePidMatch(t *testing.T, pid uint32) error {
	path, err := os.Executable()
	require.NoError(t, err)

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
	require.NoError(t, err)
}

func TestUprobePidMatchNot(t *testing.T) {
	err := uprobePidMatch(t, observertesthelper.GetMyPid()+1)
	require.Error(t, err)
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
	require.NoError(t, err)
}

func TestUprobeBinariesMatchNot(t *testing.T) {
	uprobeTest2 := testutils.RepoRootPath("contrib/tester-progs/uprobe-test-2")
	err := uprobeBinariesMatch(t, uprobeTest2)
	require.Error(t, err)
}

func TestUprobeCloneThreads(t *testing.T) {
	testutils.CaptureLog(t, logger.GetLogger())
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
	require.NoError(t, err)
}

var (
	uprobeArgsBinary  = testutils.RepoRootPath("contrib/tester-progs/uprobe-test-1")
	uprobeArgsLib     = testutils.RepoRootPath("contrib/tester-progs/libuprobe.so")
	uprobeArgsSymbols = []string{
		"uprobe_test_lib_arg1",
		"uprobe_test_lib_arg2",
		"uprobe_test_lib_arg3",
		"uprobe_test_lib_arg4",
		"uprobe_test_lib_arg5",
	}
)

func getUprobeArgsPolicy() tracingpolicy.GenericTracingPolicy {
	sel := []v1alpha1.KProbeSelector{
		{
			MatchBinaries: []v1alpha1.GenericBinarySelector{
				{
					Operator: "In",
					Values:   []string{uprobeArgsBinary},
				},
			},
		},
	}
	return tracingpolicy.GenericTracingPolicy{
		Metadata: v1.ObjectMeta{
			Name: "uprobe",
		},
		TypeMeta: v1.TypeMeta{
			Kind:       "TracingPolicy",
			APIVersion: "cilium.io/v1alpha1",
		},
		Spec: v1alpha1.TracingPolicySpec{
			UProbes: []v1alpha1.UProbeSpec{
				{
					// uprobe_test_lib_arg1
					Path: uprobeArgsLib,
					Args: []v1alpha1.KProbeArg{
						{
							Index: 0,
							Type:  "int",
						},
					},
					Selectors: sel,
				},
				{
					// uprobe_test_lib_arg2
					Path: uprobeArgsLib,
					Args: []v1alpha1.KProbeArg{
						{
							Index: 0,
							Type:  "int8",
						},
						{
							Index: 1,
							Type:  "int",
						},
					},
					Selectors: sel,
				},
				{
					// uprobe_test_lib_arg3
					Path: uprobeArgsLib,
					Args: []v1alpha1.KProbeArg{
						{
							Index: 0,
							Type:  "uint64",
						},
						{
							Index: 1,
							Type:  "uint32",
						},
						{
							Index: 2,
							Type:  "uint64",
						},
					},
					Selectors: sel,
				},
				{
					// uprobe_test_lib_arg4
					Path: uprobeArgsLib,
					Args: []v1alpha1.KProbeArg{
						{
							Index: 0,
							Type:  "int64",
						},
						{
							Index: 1,
							Type:  "int",
						},
						{
							Index: 2,
							Type:  "int8",
						},
						{
							Index: 3,
							Type:  "uint64",
						},
					},
					Selectors: sel,
				},
				{
					// uprobe_test_lib_arg5
					Path: uprobeArgsLib,
					Args: []v1alpha1.KProbeArg{
						{
							Index: 0,
							Type:  "int",
						},
						{
							Index: 1,
							Type:  "int8",
						},
						{
							Index: 2,
							Type:  "uint64",
						},
						{
							Index: 3,
							Type:  "int16",
						},
						{
							Index: 4,
							Type:  "uint64",
						},
					},
					Selectors: sel,
				},
			},
		},
	}
}

func getUprobeArgsCheckers() [5]*ec.ProcessUprobeChecker {
	checkers := [5]*ec.ProcessUprobeChecker{}

	checkers[0] = ec.NewProcessUprobeChecker("UPROBE_ARG1").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(uprobeArgsBinary))).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(123),
			))

	checkers[1] = ec.NewProcessUprobeChecker("UPROBE_ARG2").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(uprobeArgsBinary))).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(int32('a')),
				ec.NewKprobeArgumentChecker().WithIntArg(4321),
			))

	checkers[2] = ec.NewProcessUprobeChecker("UPROBE_ARG3").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(uprobeArgsBinary))).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithSizeArg(1),
				ec.NewKprobeArgumentChecker().WithUintArg(0xdeadbeef),
				ec.NewKprobeArgumentChecker().WithSizeArg(0),
			))

	checkers[3] = ec.NewProcessUprobeChecker("UPROBE_ARG4").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(uprobeArgsBinary))).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithLongArg(-321),
				ec.NewKprobeArgumentChecker().WithIntArg(-2),
				ec.NewKprobeArgumentChecker().WithIntArg(int32('b')),
				ec.NewKprobeArgumentChecker().WithSizeArg(1),
			))

	checkers[4] = ec.NewProcessUprobeChecker("UPROBE_ARG5").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(uprobeArgsBinary))).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(1),
				ec.NewKprobeArgumentChecker().WithIntArg(int32('c')),
				ec.NewKprobeArgumentChecker().WithSizeArg(0xcafe),
				ec.NewKprobeArgumentChecker().WithIntArg(1234),
				ec.NewKprobeArgumentChecker().WithSizeArg(2),
			))

	return checkers
}

func testUprobeArgs(t *testing.T, checkers [5]*ec.ProcessUprobeChecker, tp tracingpolicy.GenericTracingPolicy) {
	checker := ec.NewUnorderedEventChecker(checkers[0], checkers[1], checkers[2], checkers[3], checkers[4])

	pathConfigHook, err := yaml.Marshal(tp)
	if err != nil {
		t.Fatalf("marshal failed with %v", err)
	}

	err = os.WriteFile(testConfigFile, pathConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

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

	if err := exec.Command(uprobeArgsBinary).Run(); err != nil {
		t.Fatalf("Failed to execute test binary: %s\n", err)
	}

	err = jsonchecker.JsonTestCheck(t, checker)
	require.NoError(t, err)
}

func TestUprobeArgsWithOffset(t *testing.T) {
	f, err := elf.OpenSafeELFFile(uprobeArgsLib)
	if err != nil {
		t.Fatalf("telf.OpenSafeELFFile failed with %v", err)
	}
	defer f.Close()

	offsets := [5]uint64{}
	for idx, s := range uprobeArgsSymbols {
		offset, err := f.Offset(s)
		if err != nil {
			t.Fatalf("f.Offset failed with %v", err)
		}
		offsets[idx] = offset
	}

	checkers := getUprobeArgsCheckers()
	tp := getUprobeArgsPolicy()

	for idx := range tp.Spec.UProbes {
		tp.Spec.UProbes[idx].Offsets = []uint64{offsets[idx]}
		checkers[idx] = checkers[idx].WithOffset(offsets[idx])
	}

	testUprobeArgs(t, checkers, tp)
}

func TestUprobeArgsWithSymbol(t *testing.T) {
	checkers := getUprobeArgsCheckers()
	tp := getUprobeArgsPolicy()

	for idx := range tp.Spec.UProbes {
		tp.Spec.UProbes[idx].Symbols = []string{uprobeArgsSymbols[idx]}
		checkers[idx] = checkers[idx].WithSymbol(sm.Full(uprobeArgsSymbols[idx]))
	}

	testUprobeArgs(t, checkers, tp)
}

func TestUprobeArgsWithAddress(t *testing.T) {
	f, err := elf.OpenSafeELFFile(uprobeArgsLib)
	if err != nil {
		t.Fatalf("telf.OpenSafeELFFile failed with %v", err)
	}
	defer f.Close()

	addresses := [5]uint64{}
	for idx, s := range uprobeArgsSymbols {
		address, err := f.Address(s)
		if err != nil {
			t.Fatalf("f.Offset failed with %v", err)
		}
		addresses[idx] = address
	}

	checkers := getUprobeArgsCheckers()
	tp := getUprobeArgsPolicy()

	for idx := range tp.Spec.UProbes {
		tp.Spec.UProbes[idx].Offsets = []uint64{addresses[idx]}
		checkers[idx] = checkers[idx].WithOffset(addresses[idx])
	}

	testUprobeArgs(t, checkers, tp)
}
