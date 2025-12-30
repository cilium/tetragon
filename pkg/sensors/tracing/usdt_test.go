// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux

package tracing

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"sync"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	lc "github.com/cilium/tetragon/pkg/matchers/listmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/testutils"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
)

func TestUsdtLoadSensor(t *testing.T) {
	if !config.EnableLargeProgs() || !bpf.HasUprobeRefCtrOffset() {
		t.Skip("Need 5.3 or newer kernel for usdt and uprobe ref_ctr_off support for this test.")
	}

	var (
		sensorProgs []tus.SensorProg
		sensorMaps  []tus.SensorMap
	)

	if config.EnableV61Progs() {
		sensorProgs = []tus.SensorProg{
			0: {Name: "generic_usdt_event", Type: ebpf.Kprobe},
			1: {Name: "generic_usdt_setup_event", Type: ebpf.Kprobe},
			2: {Name: "generic_usdt_process_event", Type: ebpf.Kprobe},
			3: {Name: "generic_usdt_filter_arg", Type: ebpf.Kprobe},
			4: {Name: "generic_usdt_process_filter", Type: ebpf.Kprobe},
			5: {Name: "generic_usdt_actions", Type: ebpf.Kprobe},
			6: {Name: "generic_usdt_output", Type: ebpf.Kprobe},
		}

		sensorMaps = []tus.SensorMap{
			// all usdt programs
			{Name: "process_call_heap", Progs: []uint{0, 1, 2, 3, 4, 5, 6}},

			// all but generic_usdt_output
			{Name: "usdt_calls", Progs: []uint{0, 1, 2, 3, 4, 5}},

			// generic_usdt_process_filter
			// generic_usdt_filter_arg
			// generic_usdt_actions
			{Name: "filter_map", Progs: []uint{3, 4, 5}},

			// generic_usdt_process_event
			// generic_usdt_output
			{Name: "tcpmon_map", Progs: []uint{2, 6}},
			{Name: "tg_rb_events", Progs: []uint{2, 6}},

			// generic_usdt_event
			{Name: "tg_conf_map", Progs: []uint{0, 2, 6}},

			// shared with base sensor
			{Name: "execve_map", Progs: []uint{4, 5, 6}},
		}
	} else {
		sensorProgs = []tus.SensorProg{
			0: {Name: "generic_usdt_event", Type: ebpf.Kprobe},
			1: {Name: "generic_usdt_setup_event", Type: ebpf.Kprobe},
			2: {Name: "generic_usdt_process_event", Type: ebpf.Kprobe},
			3: {Name: "generic_usdt_filter_arg", Type: ebpf.Kprobe},
			4: {Name: "generic_usdt_process_filter", Type: ebpf.Kprobe},
			5: {Name: "generic_usdt_actions", Type: ebpf.Kprobe},
			6: {Name: "generic_usdt_output", Type: ebpf.Kprobe},
			7: {Name: "generic_usdt_path", Type: ebpf.Kprobe},
		}

		sensorMaps = []tus.SensorMap{
			// all usdt programs
			{Name: "process_call_heap", Progs: []uint{0, 1, 2, 3, 4, 5, 6, 7}},

			// all but generic_usdt_output
			{Name: "usdt_calls", Progs: []uint{0, 1, 2, 3, 4, 5, 7}},

			// generic_usdt_process_filter
			// generic_usdt_filter_arg
			// generic_usdt_actions
			{Name: "filter_map", Progs: []uint{3, 4, 5}},

			// generic_usdt_process_event
			// generic_usdt_output
			{Name: "tcpmon_map", Progs: []uint{2, 6}},
		}

		if config.EnableLargeProgs() {
			// shared with base sensor
			sensorMaps = append(sensorMaps, tus.SensorMap{Name: "execve_map", Progs: []uint{4, 5, 6}})
			if config.EnableV511Progs() {
				sensorMaps = append(sensorMaps, tus.SensorMap{Name: "tg_conf_map", Progs: []uint{0, 2, 6}})
				sensorMaps = append(sensorMaps, tus.SensorMap{Name: "tg_rb_events", Progs: []uint{2, 6}})
			} else {
				sensorMaps = append(sensorMaps, tus.SensorMap{Name: "tg_conf_map", Progs: []uint{0}})
			}
		} else {
			// shared with base sensor
			sensorMaps = append(sensorMaps, tus.SensorMap{Name: "execve_map", Progs: []uint{4}})
			sensorMaps = append(sensorMaps, tus.SensorMap{Name: "tg_conf_map", Progs: []uint{0}})
		}
	}

	usdt := testutils.RepoRootPath("contrib/tester-progs/usdt")

	nopHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "usdts"
spec:
  usdts:
  - path: "` + usdt + `"
    provider: "test"
    name: "usdt0"
`

	var sens []*sensors.Sensor
	var err error

	nopConfigHook := []byte(nopHook)
	err = os.WriteFile(testConfigFile, nopConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}
	sens, err = observertesthelper.GetDefaultSensorsWithFile(t, testConfigFile, tus.Conf().TetragonLib,
		observertesthelper.WithMyPid(), observertesthelper.WithKeepCollection())
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

func TestUsdtGeneric(t *testing.T) {
	if !config.EnableLargeProgs() || !bpf.HasUprobeRefCtrOffset() {
		t.Skip("Need 5.3 or newer kernel for usdt and uprobe ref_ctr_off support for this test.")
	}

	usdt := testutils.RepoRootPath("contrib/tester-progs/usdt")
	usdtHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "usdts"
spec:
  usdts:
  - path: "` + usdt + `"
    provider: "test"
    name: "usdt0"
`

	usdtConfigHook := []byte(usdtHook)
	err := os.WriteFile(testConfigFile, usdtConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	upChecker := ec.NewProcessUsdtChecker("USDT_GENERIC").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(usdt))).
		WithProvider(sm.Full("test")).
		WithName(sm.Full("usdt0"))

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

	if err := exec.Command(usdt).Run(); err != nil {
		t.Fatalf("Failed to execute test binary: %s\n", err)
	}

	err = jsonchecker.JsonTestCheck(t, checker)
	require.NoError(t, err)
}

func TestUsdtArgs(t *testing.T) {
	if !config.EnableLargeProgs() || !bpf.HasUprobeRefCtrOffset() {
		t.Skip("Need 5.3 or newer kernel for usdt and uprobe ref_ctr_off support for this test.")
	}

	usdt := testutils.RepoRootPath("contrib/tester-progs/usdt")
	usdtHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "usdts"
spec:
  usdts:
  - path: "` + usdt + `"
    provider: "test"
    name: "usdt0"
  - path: "` + usdt + `"
    provider: "test"
    name: "usdt3"
    args:
    - index: 0
      type: "int32"
    - index: 1
      type: "int64"
    - index: 2
      type: "uint64"
  - path: "` + usdt + `"
    provider: "test"
    name: "usdt12"
    args:
    - index: 0
      type: "int32"
    - index: 1
      type: "int32"
    - index: 2
      type: "int64"
    - index: 3
      type: "int64"
    - index: 4
      type: "int32"
  - path: "` + usdt + `"
    provider: "test"
    name: "usdt12"
    args:
    - index: 5
      type: "int64"
    - index: 6
      type: "uint64"
    - index: 7
      type: "uint64"
    - index: 8
      type: "int32"
    - index: 9
      type: "int32"
  - path: "` + usdt + `"
    provider: "test"
    name: "usdt12"
    args:
    - index: 10
      type: "int32"
    - index: 11
      type: "int32"
`
	if runtime.GOARCH == "amd64" {
		usdtHook += `
  - path: "` + usdt + `"
    provider: "test"
    name: "usdt_sib"
    args:
    - index: 0
      type: "int16"
`
	}

	usdtConfigHook := []byte(usdtHook)
	err := os.WriteFile(testConfigFile, usdtConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	upChecker_0 := ec.NewProcessUsdtChecker("USDT_GENERIC_0").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(usdt))).
		WithProvider(sm.Full("test")).
		WithName(sm.Full("usdt0"))

	upChecker_3 := ec.NewProcessUsdtChecker("USDT_GENERIC_3").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(usdt))).
		WithProvider(sm.Full("test")).
		WithName(sm.Full("usdt3")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(1),
				ec.NewKprobeArgumentChecker().WithLongArg(42),
				ec.NewKprobeArgumentChecker().WithSizeArg(0xdeadbeef),
			))

	upChecker_12_1 := ec.NewProcessUsdtChecker("USDT_GENERIC_12_1").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(usdt))).
		WithProvider(sm.Full("test")).
		WithName(sm.Full("usdt12")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(1),
				ec.NewKprobeArgumentChecker().WithIntArg(2),
				ec.NewKprobeArgumentChecker().WithLongArg(42),
				ec.NewKprobeArgumentChecker().WithLongArg(43),
				ec.NewKprobeArgumentChecker().WithIntArg(5),
			))

	upChecker_12_2 := ec.NewProcessUsdtChecker("USDT_GENERIC_12_2").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(usdt))).
		WithProvider(sm.Full("test")).
		WithName(sm.Full("usdt12")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithLongArg(6),
				ec.NewKprobeArgumentChecker().WithSizeArg(0xdeadbeef),
				ec.NewKprobeArgumentChecker().WithSizeArg(0xdeadbef7),
				ec.NewKprobeArgumentChecker().WithIntArg(-9),
				ec.NewKprobeArgumentChecker().WithIntArg(-2),
			))

	upChecker_12_3 := ec.NewProcessUsdtChecker("USDT_GENERIC_12_3").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(usdt))).
		WithProvider(sm.Full("test")).
		WithName(sm.Full("usdt12")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(-3),
				ec.NewKprobeArgumentChecker().WithIntArg(-127),
			))

	upChecker_sib := ec.NewProcessUsdtChecker("USDT_GENERIC_SIB").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(usdt))).
		WithProvider(sm.Full("test")).
		WithName(sm.Full("usdt_sib")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(-3),
			))

	checkers := []ec.EventChecker{upChecker_0, upChecker_3,
		upChecker_12_1, upChecker_12_2, upChecker_12_3}

	if runtime.GOARCH == "amd64" {
		checkers = append(checkers, upChecker_sib)
	}

	checker := ec.NewUnorderedEventChecker(checkers...)

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

	if err := exec.Command(usdt).Run(); err != nil {
		t.Fatalf("Failed to execute test binary: %s\n", err)
	}

	err = jsonchecker.JsonTestCheck(t, checker)
	require.NoError(t, err)
}

func TestUsdtGenericActionSigkill(t *testing.T) {
	if !config.EnableLargeProgs() || !bpf.HasUprobeRefCtrOffset() {
		t.Skip("Need 5.3 or newer kernel for usdt and uprobe ref_ctr_off support for this test.")
	}

	usdt := testutils.RepoRootPath("contrib/tester-progs/usdt")
	usdtHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "usdts"
spec:
  usdts:
  - path: "` + usdt + `"
    provider: "test"
    name: "usdt3"
    args:
    - index: 0
      type: "int32"
    - index: 1
      type: "int64"
    - index: 2
      type: "uint64"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Equal"
        values:
        - "1"
      - index: 1
        operator: "Equal"
        values:
        - "42"
      - index: 2
        operator: "Equal"
        values:
        - "0xdeadbeef"
      matchActions:
      - action: Sigkill
`

	usdtConfigHook := []byte(usdtHook)
	err := os.WriteFile(testConfigFile, usdtConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	upChecker := ec.NewProcessUsdtChecker("USDT_GENERIC").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(usdt))).
		WithProvider(sm.Full("test")).
		WithName(sm.Full("usdt3")).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_SIGKILL).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(1),
				ec.NewKprobeArgumentChecker().WithLongArg(42),
				ec.NewKprobeArgumentChecker().WithSizeArg(0xdeadbeef),
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

	err = exec.Command(usdt).Run()
	require.Error(t, err)

	err = jsonchecker.JsonTestCheck(t, checker)
	require.NoError(t, err)
}

func TestUsdtSet(t *testing.T) {
	if !config.EnableLargeProgs() || !bpf.HasUprobeRefCtrOffset() {
		t.Skip("Need 5.3 or newer kernel for usdt and uprobe ref_ctr_off support for this test.")
	}

	if !bpf.HasProbeWriteUserHelper() {
		t.Skip("need bpf_probe_write_user() for this test")
	}

	usdt := testutils.RepoRootPath("contrib/tester-progs/usdt-override")
	usdtHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "usdts"
spec:
  usdts:
  - path: "` + usdt + `"
    provider: "tetragon"
    name: "test_4B"
    args:
    - index: 0
      type: "int32"
    - index: 1
      type: "int32"
    - index: 2
      type: "int32"
    selectors:
    - matchActions:
      - action: Set
        argIndex: 0
        argValue: 240
`

	usdtConfigHook := []byte(usdtHook)
	err := os.WriteFile(testConfigFile, usdtConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	upChecker := ec.NewProcessUsdtChecker("USDT").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(usdt))).
		WithProvider(sm.Full("tetragon")).
		WithName(sm.Full("test_4B")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(0),
				ec.NewKprobeArgumentChecker().WithIntArg(321),
				ec.NewKprobeArgumentChecker().WithIntArg(123),
			)).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_SET)

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

	cmd := exec.Command(usdt, "321", "123")
	require.Error(t, cmd.Run())
	require.Equal(t, 240, cmd.ProcessState.ExitCode())

	err = jsonchecker.JsonTestCheck(t, checker)
	require.NoError(t, err)
}

func TestUsdtResolve(t *testing.T) {
	if !config.EnableLargeProgs() || !bpf.HasUprobeRefCtrOffset() {
		t.Skip("Need 5.3 or newer kernel for usdt and uprobe ref_ctr_off support for this test.")
	}

	if !bpf.HasProbeWriteUserHelper() {
		t.Skip("need bpf_probe_write_user() for this test")
	}

	usdt := testutils.RepoRootPath("contrib/tester-progs/usdt-resolve")
	usdtBtf := testutils.RepoRootPath("contrib/tester-progs/usdt-resolve.btf")

	tt := []struct {
		specTy    string
		filterVal int
		returnVal int
		field     string
		kpArgs    []*ec.KprobeArgumentChecker
	}{
		{"uint64", 10, 120, "v64", []*ec.KprobeArgumentChecker{
			ec.NewKprobeArgumentChecker().WithIntArg(0),
			ec.NewKprobeArgumentChecker().WithSizeArg(10), // uint64(10)
			ec.NewKprobeArgumentChecker().WithUintArg(0),
			ec.NewKprobeArgumentChecker().WithUintArg(0),
		}},
		{"uint32", 11, 130, "v32", []*ec.KprobeArgumentChecker{
			ec.NewKprobeArgumentChecker().WithIntArg(0),
			ec.NewKprobeArgumentChecker().WithSizeArg(0),
			ec.NewKprobeArgumentChecker().WithUintArg(11), // uint32(11)
			ec.NewKprobeArgumentChecker().WithUintArg(0),
		}},
		{"uint32", 12, 140, "sub.v32", []*ec.KprobeArgumentChecker{
			ec.NewKprobeArgumentChecker().WithIntArg(0),
			ec.NewKprobeArgumentChecker().WithSizeArg(0),
			ec.NewKprobeArgumentChecker().WithUintArg(0),
			ec.NewKprobeArgumentChecker().WithUintArg(12), // uint32(12)
		}},
	}

	usdtHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "usdts"
spec:
  usdts:
  - path: "` + usdt + `"
    btfPath: "` + usdtBtf + `"
    provider: "tetragon"
    name: "test"
    args:
    - index: 0
      type: "int32"
    - index: 1
      type: "` + tt[0].specTy + `"
      btfType: "mystruct"
      resolve: "` + tt[0].field + `"
    - index: 1
      type: "` + tt[1].specTy + `"
      btfType: "mystruct"
      resolve: "` + tt[1].field + `"
    - index: 1
      type: "` + tt[2].specTy + `"
      btfType: "mystruct"
      resolve: "` + tt[2].field + `"
    selectors:
    - matchArgs:
      - args: [1]
        operator: "Equal"
        values:
        - "` + strconv.Itoa(tt[0].filterVal) + `"
      matchActions:
      - action: Set
        argIndex: 0
        argValue: ` + strconv.Itoa(tt[0].returnVal) + `
    - matchArgs:
      - args: [2]
        operator: "Equal"
        values:
        - "` + strconv.Itoa(tt[1].filterVal) + `"
      matchActions:
      - action: Set
        argIndex: 0
        argValue: ` + strconv.Itoa(tt[1].returnVal) + `
    - matchArgs:
      - args: [3]
        operator: "Equal"
        values:
        - "` + strconv.Itoa(tt[2].filterVal) + `"
      matchActions:
      - action: Set
        argIndex: 0
        argValue: ` + strconv.Itoa(tt[2].returnVal) + `
`

	usdtConfigHook := []byte(usdtHook)
	err := os.WriteFile(testConfigFile, usdtConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	var checkers []ec.EventChecker
	for i := range tt {
		checkers = append(checkers, ec.NewProcessUsdtChecker("usdt-resolve").
			WithProcess(ec.NewProcessChecker().
				WithBinary(sm.Full(usdt)).
				WithArguments(
					sm.Full(tt[i].field+" "+strconv.Itoa(tt[i].filterVal)),
				),
			).WithProvider(sm.Full("tetragon")).
			WithName(sm.Full("test")).
			WithArgs(ec.NewKprobeArgumentListMatcher().
				WithOperator(lc.Ordered).
				WithValues(tt[i].kpArgs...)).
			WithAction(tetragon.KprobeAction_KPROBE_ACTION_SET))
	}

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

	for i := range tt {
		// if the argument is 10, the program should fail
		cmd := exec.Command(usdt, tt[i].field, strconv.Itoa(tt[i].filterVal))
		cmdErr := testutils.RunCmdAndLogOutput(t, cmd)
		require.Error(t, cmdErr)
		require.Equal(t, tt[i].returnVal, cmd.ProcessState.ExitCode())

		// if the argument is not 10, then the program should succeed
		cmd = exec.Command(usdt, tt[i].field, strconv.Itoa(tt[i].filterVal+1000))
		cmdErr = testutils.RunCmdAndLogOutput(t, cmd)
		require.NoError(t, cmdErr)
	}

	err = jsonchecker.JsonTestCheck(t, ec.NewUnorderedEventChecker(checkers...))
	require.NoError(t, err)
}
