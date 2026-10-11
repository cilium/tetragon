// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/testutils/policytest"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
)

func checkFentry(t *testing.T) {
	if !config.EnableV61Progs() {
		t.Skip("fentry requires at least 6.1 kernel")
	}
}

func TestFentryHeapMapConfig(t *testing.T) {
	if !bpf.HasFentryProgram() || !config.EnableLargeProgs() {
		t.Skip()
	}
	checkFentry(t)

	policy := func(opts string) string {
		return `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "fentry-heap"
spec:` + opts + `
  fentries:
  - call: "security_file_open"
    syscall: false
    return: true
    returnArg:
      index: 0
      type: "int"
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

	destroySensors := func(t *testing.T, sens []*sensors.Sensor) {
		for _, s := range sens {
			assert.NoError(t, s.Destroy(true))
		}
	}

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

	t.Run("shared", func(t *testing.T) {
		sens := loadSensors(t, policy(""))
		defer destroySensors(t, sens)

		mapsByName := findHeapMaps(sens)
		for _, name := range heapMapNames {
			maps := mapsByName[name]
			require.Len(t, maps, 2, "%s map not found in entry and exit programs", name)

			for _, m := range maps {
				assert.Equal(t, "fentry_"+name, m.PinPath)
				assert.Equal(t, uint32(defaults.DefaultFentryHeapSize), getMaxEntries(m))
			}
		}
	})

	t.Run("program", func(t *testing.T) {
		sens := loadSensors(t, policy(`
  options:
  - name: "fentry-heap-size"
    value: "1024"`))
		defer destroySensors(t, sens)

		mapsByName := findHeapMaps(sens)
		for _, name := range heapMapNames {
			maps := mapsByName[name]
			require.Len(t, maps, 2, "%s map not found in entry and exit programs", name)

			for _, m := range maps {
				assert.NotEqual(t, name, m.PinPath)
				assert.Equal(t, name, filepath.Base(m.PinPath))
				assert.Equal(t, uint32(1024), getMaxEntries(m))
			}
		}
	})
}

func TestFentryObjectLoad(t *testing.T) {
	checkFentry(t)
	testKprobeObjectLoad(t, true)
}

func TestFentryLseek(t *testing.T) {
	checkFentry(t)
	policytest.AllPolicyTests.DoObserverTest(t, "kprobe-lseek", map[string]any{
		"Hook": "fentries",
	})
}

func TestFentryObjectWriteReadHostNs(t *testing.T) {
	checkFentry(t)
	testKprobeObjectWriteReadHostNs(t, true)
}

func TestFentryObjectWriteRead(t *testing.T) {
	checkFentry(t)
	testKprobeObjectWriteRead(t, true)
}

func TestFentryObjectWriteCapsNotIn(t *testing.T) {
	checkFentry(t)
	testKprobeObjectWriteCapsNotIn(t, true)
}

func TestFentryObjectWriteReadNsOnly(t *testing.T) {
	checkFentry(t)
	testKprobeObjectWriteReadNsOnly(t, true)
}

func TestFentryObjectWriteReadPidOnly(t *testing.T) {
	checkFentry(t)
	testKprobeObjectWriteReadPidOnly(t, true)
}

func TestFentryObjectRead(t *testing.T) {
	checkFentry(t)
	testKprobeObjectRead(t, true)
}

func TestFentryObjectReadIdxMismatch(t *testing.T) {
	checkFentry(t)
	testKprobeObjectReadIdxMismatch(t, true)
}

func TestFentryObjectReadReturn(t *testing.T) {
	checkFentry(t)
	testKprobeObjectReadReturn(t, true)
}

func TestFentryObjectReturnCopy(t *testing.T) {
	checkFentry(t)
	testKprobeObjectReturnCopy(t, true)
}

func TestFentryObjectMultiValueOpen(t *testing.T) {
	checkFentry(t)
	testKprobeObjectMultiValueOpen(t, true)
}

func TestFentryObjectMultiValueOpenMount(t *testing.T) {
	checkFentry(t)
	testKprobeObjectMultiValueOpenMount(t, true)
}

func TestFentryObjectFilterOpen(t *testing.T) {
	checkFentry(t)
	testKprobeObjectFilterOpen(t, true)
}

func TestFentryObjectMultiValueFilterOpen(t *testing.T) {
	checkFentry(t)
	testKprobeObjectMultiValueFilterOpen(t, true)
}

func TestFentryObjectFilterPrefixOpen(t *testing.T) {
	checkFentry(t)
	testKprobeObjectFilterPrefixOpen(t, true)
}

func TestFentryObjectFilterPrefixOpenSuperLong(t *testing.T) {
	checkFentry(t)
	testKprobeObjectFilterPrefixOpenSuperLong(t, true)
}

func TestFentryObjectFilterPrefixOpenMount(t *testing.T) {
	checkFentry(t)
	testKprobeObjectFilterPrefixOpenMount(t, true)
}

func TestFentryObjectFilterPrefixExactOpen(t *testing.T) {
	checkFentry(t)
	testKprobeObjectFilterPrefixExactOpen(t, true)
}

func TestFentryObjectFilterPrefixExactOpenMount(t *testing.T) {
	checkFentry(t)
	testKprobeObjectFilterPrefixExactOpenMount(t, true)
}

func TestFentryObjectFilterPrefixSubdirOpen(t *testing.T) {
	checkFentry(t)
	testKprobeObjectFilterPrefixSubdirOpen(t, true)
}

func TestFentryObjectFilterPrefixSubdirOpenMount(t *testing.T) {
	checkFentry(t)
	testKprobeObjectFilterPrefixSubdirOpenMount(t, true)
}

func TestFentryObjectFilterPrefixMissOpen(t *testing.T) {
	checkFentry(t)
	testKprobeObjectFilterPrefixMissOpen(t, true)
}

func TestFentryObjectPostfixOpen(t *testing.T) {
	checkFentry(t)
	testKprobeObjectPostfixOpen(t, false, true)
}

func TestFentryObjectPostfixOpenWithNull(t *testing.T) {
	checkFentry(t)
	testKprobeObjectPostfixOpen(t, true, true)
}

func TestFentryObjectPostfixOpenSuperLong(t *testing.T) {
	checkFentry(t)
	testKprobeObjectPostfixOpenSuperLong(t, true)
}

func TestFentryObjectFilterModeOpenMatchDec(t *testing.T) {
	checkFentry(t)
	testKprobeObjectFilterModeOpenMatch(t, "%d", syscall.O_RDWR|syscall.O_TRUNC|syscall.O_CLOEXEC, syscall.O_TRUNC, true)
}

func TestFentryObjectFilterModeOpenMatchHex(t *testing.T) {
	checkFentry(t)
	testKprobeObjectFilterModeOpenMatch(t, "0x%x", syscall.O_RDWR|syscall.O_TRUNC|syscall.O_CLOEXEC, syscall.O_RDWR, true)
}

func TestFentryObjectFilterModeOpenMatchOct(t *testing.T) {
	checkFentry(t)
	testKprobeObjectFilterModeOpenMatch(t, "0%o", syscall.O_RDWR|syscall.O_TRUNC|syscall.O_CLOEXEC, syscall.O_CLOEXEC, true)
}

func TestFentryObjectFilterModeOpenFail(t *testing.T) {
	checkFentry(t)
	testKprobeObjectFilterModeOpenFail(t, true)
}

func TestFentryObjectFilenameOpen(t *testing.T) {
	checkFentry(t)
	testKprobeObjectFilenameOpen(t, true)
}

func TestFentryObjectReturnFilenameOpen(t *testing.T) {
	checkFentry(t)
	testKprobeObjectReturnFilenameOpen(t, true)
}

func TestFentryObjectFileWrite(t *testing.T) {
	checkFentry(t)
	testKprobeObjectFileWrite(t, true)
}

func TestFentryObjectFileWriteFiltered(t *testing.T) {
	checkFentry(t)
	testKprobeObjectFileWriteFiltered(t, true)
}

func TestFentryObjectFileWriteMount(t *testing.T) {
	checkFentry(t)
	testKprobeObjectFileWriteMount(t, true)
}

func TestFentryObjectFileWriteMountFiltered(t *testing.T) {
	checkFentry(t)
	testKprobeObjectFileWriteMountFiltered(t, true)
}

func TestFentryMultipleMountsFiltered(t *testing.T) {
	checkFentry(t)
	testMultipleMountsFiltered(t, true)
}

func TestFentryMultiplePathComponents(t *testing.T) {
	checkFentry(t)
	testMultiplePathComponents(t, true)
}

func TestFentryMultipleMountPath(t *testing.T) {
	checkFentry(t)
	testMultipleMountPath(t, true)
}

func TestFentryMultipleMountPathFiltered(t *testing.T) {
	checkFentry(t)
	testMultipleMountPathFiltered(t, true)
}

func TestFentryArgValues(t *testing.T) {
	checkFentry(t)
	testKprobeArgValues(t, true)
}

func TestFentry_char_iovec(t *testing.T) {
	checkFentry(t)
	testKprobe_char_iovec(t, true)
}

func TestFentry_char_iovec_overflow(t *testing.T) {
	checkFentry(t)
	testKprobe_char_iovec_overflow(t, true)
}

func TestFentry_char_iovec_returnCopy(t *testing.T) {
	checkFentry(t)
	testKprobe_char_iovec_returnCopy(t, true)
}

func TestFentryMatchArgsFileEqual(t *testing.T) {
	checkFentry(t)
	testKprobeMatchArgsFileEqual(t, true)
}

func TestFentryMatchArgsFilePostfix(t *testing.T) {
	checkFentry(t)
	testKprobeMatchArgsFilePostfix(t, true)
}

func TestFentryMatchArgsFilePrefix(t *testing.T) {
	checkFentry(t)
	testKprobeMatchArgsFilePrefix(t, true)
}

func TestFentryMatchArgsFdEqual(t *testing.T) {
	checkFentry(t)
	testKprobeMatchArgsFdEqual(t, true)
}

func TestFentryMatchArgsFdPostfix(t *testing.T) {
	checkFentry(t)
	testKprobeMatchArgsFdPostfix(t, true)
}

func TestFentryMatchArgsFdPrefix(t *testing.T) {
	checkFentry(t)
	testKprobeMatchArgsFdPrefix(t, true)
}

func TestFentrytMatchArgsFileMonitoringPrefix(t *testing.T) {
	checkFentry(t)
	testKprobeMatchArgsFileMonitoringPrefix(t, true)
}

func TestFentryMatchArgsNonPrefix(t *testing.T) {
	checkFentry(t)
	testKprobeMatchArgsNonPrefix(t, true)
}

func TestFentryMatchParentBinaries(t *testing.T) {
	checkFentry(t)
	testKprobeMatchParentBinaries(t, true)
}

func TestFentryMatchBinaries(t *testing.T) {
	checkFentry(t)
	testKprobeMatchBinaries(t, true)
}

func TestFentryMatchBinariesLargePath(t *testing.T) {
	checkFentry(t)
	testKprobeMatchBinariesLargePath(t, true)
}

func TestFentryMatchBinariesPerfring(t *testing.T) {
	checkFentry(t)
	testKprobeMatchBinariesPerfring(t, true)
}

func TestFentryMatchBinariesEarlyExec(t *testing.T) {
	checkFentry(t)
	testKprobeMatchBinariesEarlyExec(t, true)
}

func TestFentryMatchBinariesPrefixMatchArgs(t *testing.T) {
	checkFentry(t)
	testKprobeMatchBinariesPrefixMatchArgs(t, true)
}

func TestFentryBpfAttr(t *testing.T) {
	checkFentry(t)
	testKprobeBpfAttr(t, true)
}

func TestFentryWriteMaxDataTrunc(t *testing.T) {
	checkFentry(t)
	testKprobeWriteMaxDataTrunc(t, true)
}

func TestFentryWriteMaxData(t *testing.T) {
	checkFentry(t)
	testKprobeWriteMaxData(t, true)
}

func TestFentryWriteMaxDataFull(t *testing.T) {
	checkFentry(t)
	testKprobeWriteMaxDataFull(t, true)
}

func TestFentryNoRateLimit(t *testing.T) {
	checkFentry(t)
	testKprobeRateLimit(t, false, true)
}

func TestFentryRateLimit(t *testing.T) {
	checkFentry(t)
	testKprobeRateLimit(t, true, true)
}

func TestFentryListSyscallDupsRange(t *testing.T) {
	checkFentry(t)
	testKprobeListSyscallDupsRange(t, true)
}

func TestFentryKernelModuleCallsStability(t *testing.T) {
	checkFentry(t)
	testTraceKernelModuleCallsStability(t, true)
}

func TestFentryLinuxBinprmExtractPath(t *testing.T) {
	checkFentry(t)
	testLinuxBinprmExtractPath(t, true)
}

func TestFentryTraceKernelModule(t *testing.T) {
	checkFentry(t)
	testTraceKernelModule(t, true)
}

func TestFentryKernelStackTrace(t *testing.T) {
	checkFentry(t)
	testKprobeKernelStackTrace(t, true)
}

func TestFentryUserStackTrace(t *testing.T) {
	checkFentry(t)
	testKprobeUserStackTrace(t, true)
}

func TestFentryMultiMatcArgs(t *testing.T) {
	checkFentry(t)
	testKprobeMultiMatcArgs(t, true)
}

func TestFentryArgs(t *testing.T) {
	checkFentry(t)
	testKprobeArgs(t, true)
}

func TestFentryProcessSetCap(t *testing.T) {
	checkFentry(t)
	testProcessSetCap(t, true)
}

func TestFentryMissedProgStatsKprobeMulti(t *testing.T) {
	t.Skip("TODO")
}

func TestFentryBpfCmd(t *testing.T) {
	checkFentry(t)
	testKprobeBpfCmd(t, true)
}

func TestFentryMultiSymbolInstancesOk(t *testing.T) {
	checkFentry(t)
	testKprobeMultiSymbolInstancesOk(t, true)
}

func TestFentryLongPath(t *testing.T) {
	checkFentry(t)
	testLongPath(t, true)
}

func TestFentryMaxPath(t *testing.T) {
	checkFentry(t)
	testMaxPath(t, true)
}

func TestFentryDentryPath(t *testing.T) {
	checkFentry(t)
	testKprobeDentryPath(t, true)
}

func TestFentryResolvePid(t *testing.T) {
	checkFentry(t)
	testKprobeResolvePid(t, true)
}

func TestFentryArgsReverse(t *testing.T) {
	checkFentry(t)
	testKprobeArgsReverse(t, true)
}

func TestFentryResolveSecondArg(t *testing.T) {
	checkFentry(t)
	testKprobeResolveSecondArg(t, true)
}

func TestFentryIgnore(t *testing.T) {
	checkFentry(t)
	testKprobeIgnore(t, true)
}

func TestFentryArgsMulti(t *testing.T) {
	checkFentry(t)
	testKprobeArgsMulti(t, true)
}

func TestFentryArgsMultiResolve(t *testing.T) {
	checkFentry(t)
	testKprobeArgsMultiResolve(t, true)
}

func TestFentryArgsFilter(t *testing.T) {
	checkFentry(t)
	testKprobeArgsFilter(t, true)
}

func TestFentryCapabilitiesGained(t *testing.T) {
	checkFentry(t)
	testCapabilitiesGained(t, true)
}

func TestFentryResolveCurrent(t *testing.T) {
	checkFentry(t)
	testKprobeResolveCurrent(t, true)
}

func TestFentryRangeIn(t *testing.T) {
	checkFentry(t)
	testKprobeRangeOp(t, true, true)
}

func TestFentryRangeNotIn(t *testing.T) {
	checkFentry(t)
	testKprobeRangeOp(t, false, true)
}

func TestFentryGTOk(t *testing.T) {
	checkFentry(t)
	testKprobeGT(t, 0xffff1, false, true)
}

func TestFentryGTFail(t *testing.T) {
	checkFentry(t)
	testKprobeGT(t, 0xfffef, true, true)
}

func TestFentryFileTypeFilterRegular(t *testing.T) {
	checkFentry(t)
	testKprobeFileTypeFilterRegular(t, true)
}

func TestFentryFileTypeFilterPipe(t *testing.T) {
	checkFentry(t)
	testKprobeFileTypeFilterPipe(t, true)
}

func TestFentryFileTypeFilterNotRegular(t *testing.T) {
	checkFentry(t)
	testKprobeFileTypeFilterNotRegular(t, true)
}

func TestFentryFileTypeFilterSocket(t *testing.T) {
	checkFentry(t)
	testKprobeFileTypeFilterSocket(t, true)
}

func TestFentryFileTypeFilterNotPipe(t *testing.T) {
	checkFentry(t)
	testKprobeFileTypeFilterNotPipe(t, true)
}

func TestFentryFileTypeFilterMultiple(t *testing.T) {
	checkFentry(t)
	testKprobeFileTypeFilterMultiple(t, true)
}

func TestFentryNotEqualMultipleValues(t *testing.T) {
	checkFentry(t)
	testKprobeNotEqualMultipleValues(t, true)
}

func TestSubStringLinuxBinprmFentry(t *testing.T) {
	checkFentry(t)
	policytest.AllPolicyTests.DoObserverTest(t, "kprobe-substring-linux-binprm", map[string]any{
		"Hook": "fentries",
	})
}

func TestSubStringFileFentry(t *testing.T) {
	checkFentry(t)
	policytest.AllPolicyTests.DoObserverTest(t, "kprobe-substring-file", map[string]any{
		"Hook": "fentries",
	})
}

func TestSubStringPathFentry(t *testing.T) {
	checkFentry(t)
	policytest.AllPolicyTests.DoObserverTest(t, "kprobe-substring-path", map[string]any{
		"Hook": "fentries",
	})
}

func TestFdRetrivalFentry(t *testing.T) {
	checkFentry(t)
	policytest.AllPolicyTests.DoObserverTest(t, "kprobe-fd-arg", map[string]any{
		"Hook": "fentries",
	})
}
