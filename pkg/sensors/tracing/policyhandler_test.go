//go:build !windows

package tracing

import (
	"context"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/config"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/arch"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	lc "github.com/cilium/tetragon/pkg/matchers/listmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"

	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/testutils"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

func TestPolicyHandler(t *testing.T) {
	if !config.EnableLargeProgs() || !bpf.HasUprobeRefCtrOffset() {
		t.Skip("Need 5.3 or newer kernel for usdt and uprobe ref_ctr_off support for this test.")
	}

	usdt := testutils.RepoRootPath("contrib/tester-progs/usdt")
	testUretprobe := testutils.RepoRootPath("contrib/tester-progs/uretprobe")
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	hook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "test-multi-sensors"
spec:
  uprobes:
  - path: "` + testUretprobe + `"
    symbols:
    - "return_string"
  usdts:
  - path: "` + usdt + `"
    provider: "test"
    name: "usdt0"
  lists:
  - name: "test"
    type: "syscalls"
    values:
    - "sys_dup"
  tracepoints:
  - subsystem: "raw_syscalls"
    event: "sys_enter"
    args:
    - index: 4
      type: "syscall64"
    - index: 5
      type: "uint64"
    selectors:
    - matchPIDs:
      - operator: In
        followForks: true
        isNamespacePID: false
        values:
        - ` + pidStr + `
      matchArgs:
      - index: 0
        operator: "InMap"
        values:
        - "list:test"
  kprobes:
  - call: "sys_writev"
    return: false
    syscall: true
    args:
    - index: 0
      type: "int"
`
	// Skipped lsm sensor because it requires kernel to support it,
	// and in go tests ubuntu 24.04 CI we don't.

	tp, err := tracingpolicy.FromYAML(hook)
	require.NoError(t, err)

	newSensors, err := sensors.SensorsFromPolicy(tp, policyfilter.NoFilterID)
	require.NoError(t, err)
	require.Len(t, newSensors, 4)

	for idx, sens := range newSensors {
		switch idx {
		// sensors are always sorted; let's test it too!
		case 0:
			require.Equal(t, "generic_kprobe", sens.GetName())
		case 1:
			require.Equal(t, "generic_tracepoint", sens.GetName())
		case 2:
			require.Equal(t, "generic_uprobe", sens.GetName())
		case 3:
			require.Equal(t, "generic_usdt", sens.GetName())
		}
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	createCrdFile(t, hook)
	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	kprobeCheck := kprobeChecker(t)
	require.NotNil(t, kprobeCheck)
	usdtCheck := usdtChecker(t, usdt)
	require.NotNil(t, usdtCheck)
	uprobeCheck := uprobeChecker(t, testUretprobe)
	require.NotNil(t, uprobeCheck)
	tpCheck := tracepointChecker(t)
	require.NotNil(t, tpCheck)

	checker := ec.NewUnorderedEventChecker(kprobeCheck, usdtCheck, uprobeCheck, tpCheck)
	require.NoError(t, jsonchecker.JsonTestCheck(t, checker))
}

func usdtChecker(t *testing.T, usdt string) *ec.ProcessUsdtChecker {
	err := exec.Command(usdt).Run()
	require.NoError(t, err)

	return ec.NewProcessUsdtChecker("USDT_GENERIC").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(usdt))).
		WithProvider(sm.Full("test")).
		WithName(sm.Full("usdt0"))
}

func uprobeChecker(t *testing.T, testUretprobe string) *ec.ProcessUprobeChecker {
	err := exec.Command(testUretprobe).Run()
	require.NoError(t, err)

	return ec.NewProcessUprobeChecker("URETPROBE_GENERIC").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(testUretprobe))).
		WithSymbol(sm.Full("return_string"))
}

func kprobeChecker(t *testing.T) *ec.ProcessKprobeChecker {
	err := helloIovecWorldWritev()
	require.NoError(t, err)

	return ec.NewProcessKprobeChecker("KPROBE_GENERIC").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Suffix(tus.Conf().SelfBinary))).
		WithFunctionName(sm.Full(arch.AddSyscallPrefixTestHelper(t, "sys_writev"))).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(1)))
}

func tracepointChecker(t *testing.T) *ec.ProcessTracepointChecker {
	syscall.Dup(9910)
	return ec.NewProcessTracepointChecker("TRACEPOINT_GENERIC").
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithSyscallId(mkSysIDChecker(t, unix.SYS_DUP)),
				ec.NewKprobeArgumentChecker().WithSizeArg(uint64(9910)),
			))
}
