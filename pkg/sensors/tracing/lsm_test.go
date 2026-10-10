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
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/kernels"
	lc "github.com/cilium/tetragon/pkg/matchers/listmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/testutils"
	"github.com/cilium/tetragon/pkg/testutils/policytest"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
)

func TestLSMCgTrackerMap(t *testing.T) {
	if !bpf.HasLSMPrograms() || !config.EnableLargeProgs() {
		t.Skip()
	}

	// Store original setting to restore later
	originalCgTrackerID := option.Config.EnableCgTrackerID
	defer func() {
		option.Config.EnableCgTrackerID = originalCgTrackerID
	}()

	// Define our test policy
	configHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "lsm-cgtracker-test"
spec:
  lsmhooks:
  - hook: "file_open"
    args:
      - index: 0
        type: "file"
`

	createCrdFile(t, configHook)

	// Test both cases: disabled and enabled cgtracker
	testCases := []struct {
		name            string
		enableCgTracker bool
		expectMapFound  bool
	}{
		{
			name:            "With EnableCgTrackerID = false",
			enableCgTracker: false,
			expectMapFound:  false,
		},
		{
			name:            "With EnableCgTrackerID = true",
			enableCgTracker: true,
			expectMapFound:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Apply the test case configuration
			option.Config.EnableCgTrackerID = tc.enableCgTracker
			t.Logf("Running with EnableCgTrackerID = %v", option.Config.EnableCgTrackerID)

			// Load sensors with current config
			sens, err := observertesthelper.GetDefaultSensorsWithFile(
				t, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
			if err != nil {
				t.Fatalf("GetDefaultSensorsWithFile error: %s", err)
			}

			// Verify map presence matches expectations
			mapFound := false
			for _, sensor := range sens {
				for _, m := range sensor.Maps {
					if m.Name == "tg_cgtracker_map" {
						mapFound = true
						t.Logf("Found tg_cgtracker_map in sensor %s", sensor.Name)
						break
					}
				}
				if mapFound {
					break
				}
			}

			if tc.expectMapFound {
				require.True(t, mapFound, "tg_cgtracker_map should be present when EnableCgTrackerID is true")
			} else {
				require.False(t, mapFound, "tg_cgtracker_map should NOT be present when EnableCgTrackerID is false")
			}

			// Clean up sensors before next test case
			sensi := make([]sensors.SensorIface, 0, len(sens))
			for _, s := range sens {
				sensi = append(sensi, s)
			}
			sensors.UnloadSensors(sensi)
		})
	}
}

func TestLSMOpenFile(t *testing.T) {
	if !bpf.HasLSMPrograms() || !config.EnableLargeProgs() {
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

	createCrdFile(t, configHook)

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
	require.NoError(t, err)
}

func TestLSMOverrideAction(t *testing.T) {
	if !bpf.HasLSMPrograms() || !config.EnableLargeProgs() {
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

	createCrdFile(t, configHook)

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
	require.NoError(t, err)
}

func TestLSMIMAHash(t *testing.T) {
	if !bpf.HasLSMPrograms() || !config.EnableLargeProgs() || !kernels.MinKernelVersion("6.0") {
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

	createCrdFile(t, configHook)

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
	require.Condition(t, checkFunc)
}

func TestLSMDuplicateHooks(t *testing.T) {
	policytest.AllPolicyTests.DoObserverTest(t, "lsm-dup-hooks", nil)
}

func TestLSMHeapMapConfig(t *testing.T) {
	if !bpf.HasLSMPrograms() || !config.EnableLargeProgs() {
		t.Skip()
	}

	// opts is the options block (may be empty)
	policy := func(opts string) string {
		return `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "lsm-heap"
spec:` + opts + `
  lsmhooks:
  - hook: "file_open"
    args:
      - index: 0
        type: "file"
`
	}

	loadSensors := func(t *testing.T, config string) []*sensors.Sensor {
		createCrdFile(t, config)
		sens, err := observertesthelper.GetDefaultSensorsWithFile(t, testConfigFile,
			tus.Conf().TetragonLib, observertesthelper.WithKeepCollection())
		require.NoError(t, err)
		return sens
	}

	unloadSensors := func(sens []*sensors.Sensor) {
		sensi := make([]sensors.SensorIface, 0, len(sens))
		for _, s := range sens {
			sensi = append(sensi, s)
		}
		sensors.UnloadSensors(sensi)
	}

	// all the per-process heap maps (see getHeapMaps in generic.go)
	heapMapNames := []string{
		"process_call_heap",
		"buffer_heap_map",
		"string_maps_heap",
		"string_prefix_maps_heap",
		"string_postfix_maps_heap",
		"ratelimit_heap",
	}

	findHeapMaps := func(sens []*sensors.Sensor) map[string][]*program.Map {
		maps := make(map[string][]*program.Map)
		for _, s := range sens {
			for _, m := range s.Maps {
				for _, name := range heapMapNames {
					if m.Name == name {
						maps[name] = append(maps[name], m)
					}
				}
			}
		}
		return maps
	}

	getMaxEntries := func(m *program.Map) uint32 {
		path := filepath.Join(bpf.MapPrefixPath(), m.PinPath)
		val, err := program.GetMaxEntriesPinnedMap(path)
		require.NoError(t, err)
		return val
	}

	// heap maps as MapShared at global scope (/sys/fs/bpf/tetragon/lsm_<name>),
	// for both core and output programs
	t.Run("shared", func(t *testing.T) {
		sens := loadSensors(t, policy(""))
		defer unloadSensors(sens)

		mapsByName := findHeapMaps(sens)
		for _, name := range heapMapNames {
			maps := mapsByName[name]
			require.Len(t, maps, 2, "%s map not found in core and output programs", name)

			for _, m := range maps {
				assert.Equal(t, "lsm_"+name, m.PinPath)
				assert.Equal(t, uint32(defaults.DefaultLsmHeapSize), getMaxEntries(m))
			}
		}
	})

	// heap maps as MapBuilderProgram at program scope
	// (.../policy/sensor/prog/<name>), shared by core and output programs
	t.Run("program", func(t *testing.T) {
		sens := loadSensors(t, policy(`
  options:
  - name: "lsm-heap-size"
    value: "1024"`))
		defer unloadSensors(sens)

		mapsByName := findHeapMaps(sens)
		for _, name := range heapMapNames {
			maps := mapsByName[name]
			require.Len(t, maps, 2, "%s map not found in core and output programs", name)
			assert.Equal(t, maps[0].PinPath, maps[1].PinPath)

			for _, m := range maps {
				assert.NotEqual(t, name, m.PinPath)
				assert.Equal(t, name, filepath.Base(m.PinPath))
				assert.Equal(t, uint32(1024), getMaxEntries(m))
			}
		}
	})
}
