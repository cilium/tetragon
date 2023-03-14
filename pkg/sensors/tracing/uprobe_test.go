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
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/testutils"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/stretchr/testify/assert"
)

func TestUprobeLoad(t *testing.T) {
	var sensorProgs = []tus.SensorProg{
		// uprobe
		0:  tus.SensorProg{Name: "generic_uprobe_event", Type: ebpf.Kprobe},
		1:  tus.SensorProg{Name: "generic_uprobe_process_event0", Type: ebpf.Kprobe},
		2:  tus.SensorProg{Name: "generic_uprobe_process_event1", Type: ebpf.Kprobe},
		3:  tus.SensorProg{Name: "generic_uprobe_process_event2", Type: ebpf.Kprobe},
		4:  tus.SensorProg{Name: "generic_uprobe_process_event3", Type: ebpf.Kprobe},
		5:  tus.SensorProg{Name: "generic_uprobe_process_event4", Type: ebpf.Kprobe},
		6:  tus.SensorProg{Name: "generic_uprobe_filter_arg1", Type: ebpf.Kprobe},
		7:  tus.SensorProg{Name: "generic_uprobe_filter_arg2", Type: ebpf.Kprobe},
		8:  tus.SensorProg{Name: "generic_uprobe_filter_arg3", Type: ebpf.Kprobe},
		9:  tus.SensorProg{Name: "generic_uprobe_filter_arg4", Type: ebpf.Kprobe},
		10: tus.SensorProg{Name: "generic_uprobe_filter_arg5", Type: ebpf.Kprobe},
		11: tus.SensorProg{Name: "generic_uprobe_process_filter", Type: ebpf.Kprobe},
	}

	var sensorMaps = []tus.SensorMap{
		// all uprobe programs
		tus.SensorMap{Name: "process_call_heap", Progs: []uint{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}},
		tus.SensorMap{Name: "uprobe_calls", Progs: []uint{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}},

		// generic_uprobe_process_filter,generic_uprobe_filter_arg*
		tus.SensorMap{Name: "filter_map", Progs: []uint{6, 7, 8, 9, 10, 11}},

		// generic_uprobe_filter_arg*,generic_retuprobe_event,base
		tus.SensorMap{Name: "tcpmon_map", Progs: []uint{6, 7, 8, 9, 10, 12}},

		// shared with base sensor
		tus.SensorMap{Name: "execve_map", Progs: []uint{6, 7, 8, 9, 10, 11, 12}},
	}

	nopHook := `
apiVersion: cilium.io/v1alpha1
metadata:
  name: "uprobe"
spec:
  uprobes:
  - path: "/bin/bash"
    symbol: "main"
`

	var sens []*sensors.Sensor
	var err error

	nopConfigHook := []byte(nopHook)
	err = os.WriteFile(testConfigFile, nopConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}
	sens, err = observer.GetDefaultSensorsWithFile(t, context.TODO(), testConfigFile, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}

	tus.CheckSensorLoad(sens, sensorMaps, sensorProgs, t)

	sensors.UnloadAll(tus.Conf().TetragonLib)
}

func TestUprobeGeneric(t *testing.T) {
	testNop := testutils.RepoRootPath("contrib/tester-progs/nop")
	nopHook := `
apiVersion: cilium.io/v1alpha1
metadata:
  name: "uprobe"
spec:
  uprobes:
  - path: "` + testNop + `"
    symbol: "main"
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

	obs, err := observer.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
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
metadata:
  name: "uprobe"
spec:
  uprobes:
  - path: "` + path + `"
    symbol: "uprobe_test_func"
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

	obs, err := observer.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	UprobeTestFunc()

	return jsonchecker.JsonTestCheck(t, checker)
}

func TestUprobePidMatch(t *testing.T) {
	err := uprobePidMatch(t, observer.GetMyPid())
	assert.NoError(t, err)
}

func TestUprobePidMatchNot(t *testing.T) {
	err := uprobePidMatch(t, observer.GetMyPid()+1)
	assert.Error(t, err)
}
