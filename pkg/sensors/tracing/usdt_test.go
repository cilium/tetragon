// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"context"
	"os"
	"os/exec"
	"sync"
	"testing"

	"github.com/cilium/ebpf"
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
	"github.com/stretchr/testify/require"
)

func TestUsdtLoadSensor(t *testing.T) {
	if !config.EnableLargeProgs() || !bpf.HasUprobeRefCtrOffset() {
		t.Skip("Need 5.3 or newer kernel for usdt and uprobe ref_ctr_off support for this test.")
	}

	var sensorProgs = []tus.SensorProg{
		0: {Name: "generic_usdt_event", Type: ebpf.Kprobe},
		1: {Name: "generic_usdt_setup_event", Type: ebpf.Kprobe},
		2: {Name: "generic_usdt_process_event", Type: ebpf.Kprobe},
		3: {Name: "generic_usdt_filter_arg", Type: ebpf.Kprobe},
		4: {Name: "generic_usdt_process_filter", Type: ebpf.Kprobe},
		5: {Name: "generic_usdt_actions", Type: ebpf.Kprobe},
		6: {Name: "generic_usdt_output", Type: ebpf.Kprobe},
	}

	var sensorMaps = []tus.SensorMap{
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

		// generic_usdt_event
		{Name: "tg_conf_map", Progs: []uint{0}},
	}

	if config.EnableLargeProgs() {
		// shared with base sensor
		sensorMaps = append(sensorMaps, tus.SensorMap{Name: "execve_map", Progs: []uint{4, 5, 6}})
	} else {
		// shared with base sensor
		sensorMaps = append(sensorMaps, tus.SensorMap{Name: "execve_map", Progs: []uint{4}})
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

	checker := ec.NewUnorderedEventChecker(upChecker_0, upChecker_3,
		upChecker_12_1, upChecker_12_2, upChecker_12_3)

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
