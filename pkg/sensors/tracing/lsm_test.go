// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/kernels"
	lc "github.com/cilium/tetragon/pkg/matchers/listmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/testutils"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/stretchr/testify/assert"
)

func TestLSMObjectLoad(t *testing.T) {
	if !bpf.HasLSMPrograms() || !kernels.EnableLargeProgs() {
		t.Skip()
	}

	var sensorProgs = []tus.SensorProg{
		// lsm
		0: tus.SensorProg{Name: "generic_lsm_event", Type: ebpf.LSM},
		1: tus.SensorProg{Name: "generic_lsm_setup_event", Type: ebpf.LSM},
		2: tus.SensorProg{Name: "generic_lsm_process_event", Type: ebpf.LSM},
		3: tus.SensorProg{Name: "generic_lsm_filter_arg", Type: ebpf.LSM},
		4: tus.SensorProg{Name: "generic_lsm_process_filter", Type: ebpf.LSM},
		5: tus.SensorProg{Name: "generic_lsm_actions", Type: ebpf.LSM},
		6: tus.SensorProg{Name: "generic_lsm_output", Type: ebpf.LSM},
	}
	var sensorMaps = []tus.SensorMap{
		// all LSM programs
		tus.SensorMap{Name: "process_call_heap", Progs: []uint{0, 1, 2, 3, 4, 5, 6}},

		// all but generic_lsm_output
		tus.SensorMap{Name: "lsm_calls", Progs: []uint{0, 1, 2, 3, 4, 5}},

		// generic_lsm_process_filter,generic_lsm_filter_arg,
		// generic_lsm_actions
		tus.SensorMap{Name: "filter_map", Progs: []uint{3, 4, 5}},

		// generic_lsm_actions, generic_lsm_output
		tus.SensorMap{Name: "override_tasks", Progs: []uint{5, 6}},

		// all lsm but generic_lsm_process_filter
		tus.SensorMap{Name: "config_map", Progs: []uint{0, 1, 2}},

		// generic_lsm_event
		tus.SensorMap{Name: "tg_conf_map", Progs: []uint{0}},

		// shared with base sensor
		tus.SensorMap{Name: "execve_map", Progs: []uint{4, 5, 6}},

		// generic_lsm_process_event*,generic_lsm_output
		tus.SensorMap{Name: "tcpmon_map", Progs: []uint{1, 2, 6}},
	}

	configHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "lsm"
spec:
  lsmhooks:
  - hook: "file_open"
    args:
      - index: 0
        type: "file"
`

	configHookRaw := []byte(configHook)
	err := os.WriteFile(testConfigFile, configHookRaw, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}
	sens, err := observertesthelper.GetDefaultSensorsWithFile(t, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
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

func TestLSMOpenFile(t *testing.T) {
	if !bpf.HasLSMPrograms() || !kernels.EnableLargeProgs() {
		t.Skip()
	}
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	testBin := testutils.RepoRootPath("contrib/tester-progs/direct-write-tester")
	tempFile := directWriteTempFile(t)

	configHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "lsm"
spec:
  lsmhooks:
  - hook: "file_open"
    args:
      - index: 0
        type: "file"
    selectors:
    - matchBinaries:
      - operator: "In"
        values:
        - "` + testBin + `"
      matchArgs:
      - index: 0
        operator: "Equal"
        values:
        - "` + tempFile + `"
`

	configHookRaw := []byte(configHook)
	err := os.WriteFile(testConfigFile, configHookRaw, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}
	lsmChecker := ec.NewProcessLsmChecker("lsm-file-checker").
		WithFunctionName(sm.Suffix("file_open")).
		WithProcess(ec.NewProcessChecker().WithBinary(sm.Full(testBin))).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithFileArg(ec.NewKprobeFileChecker().WithPath(sm.Full(tempFile)))))
	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	testCmd := exec.Command(testBin, tempFile)

	if err := testCmd.Run(); err != nil {
		t.Fatalf("failed to run %s: %s", testCmd, err)
	}

	err = jsonchecker.JsonTestCheck(t, ec.NewUnorderedEventChecker(lsmChecker))
	assert.NoError(t, err)
}

func TestLSMOverrideAction(t *testing.T) {
	if !bpf.HasLSMPrograms() || !kernels.EnableLargeProgs() {
		t.Skip()
	}
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	testBin := testutils.RepoRootPath("contrib/tester-progs/nop")
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))

	configHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "lsm"
spec:
  lsmhooks:
  - hook: "bprm_check_security"
    args:
      - index: 0
        type: "linux_binprm"
    selectors:
    - matchPIDs:
      - operator: In
        followForks: true
        isNamespacePID: false
        values:
        - ` + pidStr + `
      matchArgs:
        - index: 0
          operator: "Postfix"
          values:
          - "` + testBin + `"
      matchActions:
      - action: Override
        argError: -1
`

	configHookRaw := []byte(configHook)
	err := os.WriteFile(testConfigFile, configHookRaw, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}
	lsmChecker := ec.NewProcessLsmChecker("lsm-file-checker").
		WithFunctionName(sm.Suffix("bprm_check_security")).
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Suffix(tus.Conf().SelfBinary))).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithLinuxBinprmArg(ec.NewKprobeLinuxBinprmChecker().WithPath(sm.Full(testBin))))).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_OVERRIDE)
	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	testCmd := exec.Command(testBin)

	testCmd.Run()

	assert.Equal(t, -1, testCmd.ProcessState.ExitCode(), "Exit code should be -1")

	err = jsonchecker.JsonTestCheck(t, ec.NewUnorderedEventChecker(lsmChecker))
	assert.NoError(t, err)
}

func TestLSMIMAHash(t *testing.T) {
	if !bpf.HasLSMPrograms() || !kernels.EnableLargeProgs() || !kernels.MinKernelVersion("6.0") {
		t.Skip()
	}
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	testBin := testutils.RepoRootPath("contrib/tester-progs/nop")
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))

	configHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "lsm"
spec:
  lsmhooks:
  - hook: "bprm_check_security"
    args:
      - index: 0
        type: "linux_binprm"
    selectors:
    - matchPIDs:
      - operator: In
        followForks: true
        isNamespacePID: false
        values:
        - ` + pidStr + `
      matchActions:
      - action: Post
        imaHash: true
`

	configHookRaw := []byte(configHook)
	err := os.WriteFile(testConfigFile, configHookRaw, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}
	hasherSha256 := sha256.New()
	hasherSha1 := sha1.New()
	s, err := os.ReadFile(testBin)
	if err != nil {
		t.Fatalf("ReadFile(%s): err %s", testBin, err)
	}
	hasherSha256.Write(s)
	hasherSha1.Write(s)
	lsmCheckerSha256 := ec.NewProcessLsmChecker("lsm-ima-checker").
		WithFunctionName(sm.Suffix("bprm_check_security")).
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Suffix(tus.Conf().SelfBinary))).
		WithImaHash(sm.Full("sha256:" + hex.EncodeToString(hasherSha256.Sum(nil))))
	lsmCheckerSha1 := ec.NewProcessLsmChecker("lsm-ima-checker").
		WithFunctionName(sm.Suffix("bprm_check_security")).
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Suffix(tus.Conf().SelfBinary))).
		WithImaHash(sm.Full("sha1:" + hex.EncodeToString(hasherSha1.Sum(nil))))
	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	testCmd := exec.Command(testBin)

	if err := testCmd.Run(); err != nil {
		t.Fatalf("failed to run %s: %s", testCmd, err)
	}

	err = jsonchecker.JsonTestCheck(t, ec.NewUnorderedEventChecker(lsmCheckerSha256))
	err2 := jsonchecker.JsonTestCheck(t, ec.NewUnorderedEventChecker(lsmCheckerSha1))
	checkFunc := func() bool {
		if err != nil && err2 != nil {
			return false
		}
		return true
	}
	assert.Condition(t, checkFunc)
}
