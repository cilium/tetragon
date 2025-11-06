// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build amd64 && linux

package tracing

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	lc "github.com/cilium/tetragon/pkg/matchers/listmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/testutils"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
)

func TestUprobeOverrideAction(t *testing.T) {
	if !bpf.HasUprobeRegsChange() {
		t.Skip("skipping regs override action test, regs override is not supported in kernel")
	}

	testBinary := testutils.RepoRootPath("contrib/tester-progs/regs-override")

	// Put uprobe at the beginning of test_1 function and make sure
	// uprobe overrides test_1 return value (with 123).

	pathHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe"
spec:
  uprobes:
  - path: "` + testBinary + `"
    symbols:
    - "test_1"
    selectors:
    - matchActions:
      - action: Override
        argError: 123
`

	pathConfigHook := []byte(pathHook)
	err := os.WriteFile(testConfigFile, pathConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	upChecker := ec.NewProcessUprobeChecker("UPROBE_OVERRIDE").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(testBinary))).
		WithSymbol(sm.Full("test_1"))
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

	cmd := exec.Command(testBinary, "1")
	require.Error(t, cmd.Run())
	require.Equal(t, 123, cmd.ProcessState.ExitCode())

	err = jsonchecker.JsonTestCheck(t, checker)
	require.NoError(t, err)
}

func TestUprobeOverrideRegsAction(t *testing.T) {
	if !bpf.HasUprobeRegsChange() {
		t.Skip("skipping regs override action test, regs override is not supported in kernel")
	}

	testBinary := testutils.RepoRootPath("contrib/tester-progs/regs-override")

	// Put uprobe in test_1 function at:
	//
	//     "push   %rbp\n"         /* +0  55             */
	//     "mov    %rsp,%rbp\n"    /* +1  48 89 e5       */
	//     "mov    $0x1,%eax\n"    /* +4  b8 01 00 00 00 */
	// --> "mov    $0x3,%eax\n"    /* +9  b8 03 00 00 00 */
	//     "pop    %rbp\n"         /* +14 5d             */
	//     "ret\n"                 /* +15 c3             */
	//
	// Make sure uprobe overrides test_1 return value (with 11)
	// and the rest of the function is not executed.

	pathHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe"
spec:
  uprobes:
  - path: "` + testBinary + `"
    symbols:
    - "test_1+9"
    selectors:
    - matchActions:
      - action: Override
        argRegs:
        - "rax=11"
        - "rbp=(%rsp)"
        - "rip=8(%rsp)"
        - "rsp=8%rsp"
`

	pathConfigHook := []byte(pathHook)
	err := os.WriteFile(testConfigFile, pathConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	upChecker := ec.NewProcessUprobeChecker("UPROBE_BINARIES_MATCH").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(testBinary))).
		WithSymbol(sm.Full("test_1+9"))
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

	cmd := exec.Command(testBinary, "1")
	require.Error(t, cmd.Run())
	require.Equal(t, 11, cmd.ProcessState.ExitCode())

	err = jsonchecker.JsonTestCheck(t, checker)
	require.NoError(t, err)
}

func TestUprobeResolve(t *testing.T) {
	if !config.EnableLargeProgs() || !bpf.HasUprobeRefCtrOffset() {
		t.Skip("Need 5.3 or newer kernel for uprobe ref_ctr_off support for this test.")
	}

	if !bpf.HasProbeWriteUserHelper() {
		t.Skip("need bpf_probe_write_user() for this test")
	}

	uprobe := testutils.RepoRootPath("contrib/tester-progs/uprobe-resolve")
	uprobeBtf := testutils.RepoRootPath("contrib/tester-progs/uprobe-resolve.btf")

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

	uprobeHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe"
spec:
  uprobes:
  - path: "` + uprobe + `"
    btfPath: "` + uprobeBtf + `"
    symbols:
    - "func"
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
`

	uprobeConfigHook := []byte(uprobeHook)
	err := os.WriteFile(testConfigFile, uprobeConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	var checkers []ec.EventChecker
	for i := range tt {
		checkers = append(checkers, ec.NewProcessUprobeChecker("uprobe-resolve").
			WithProcess(ec.NewProcessChecker().
				WithBinary(sm.Full(uprobe)).
				WithArguments(
					sm.Full(tt[i].field+" "+strconv.Itoa(tt[i].filterVal)),
				),
			).WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(tt[i].kpArgs...)))
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
		cmd := exec.Command(uprobe, tt[i].field, strconv.Itoa(tt[i].filterVal))
		cmdErr := testutils.RunCmdAndLogOutput(t, cmd)
		require.NoError(t, cmdErr)
	}

	err = jsonchecker.JsonTestCheck(t, ec.NewUnorderedEventChecker(checkers...))
	require.NoError(t, err)
}

func testUprobeOverrideRegsActionSize(t *testing.T, ass, num string) {
	if !bpf.HasUprobeRegsChange() {
		t.Skip("skipping regs override action test, regs override is not supported in kernel")
	}

	testBinary := testutils.RepoRootPath("contrib/tester-progs/regs-override")

	// Put uprobe in test_2 function at:
	//
	//       "push   %rbp\n"                        /* +0  55                            */
	//       "mov    %rsp,%rbp\n"                   /* +1  48 89 e5                      */
	//       "mov    $0xdeadbeef00000000,%rax\n"    /* +4  48 b8 00 00 00 00 ef be ad de */
	//  -->  "pop    %rbp\n"                        /* +14 5d                            */
	//       "ret\n"                                /* +15 c3                            */
	//
	// Make sure uprobe overrides test_1 return value (with 11)
	// and the rest of the function is not executed.

	pathHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe"
spec:
  uprobes:
  - path: "` + testBinary + `"
    symbols:
    - "test_2+14"
    selectors:
    - matchActions:
      - action: Override
        argRegs:
        - "` + ass + `"
`

	pathConfigHook := []byte(pathHook)
	err := os.WriteFile(testConfigFile, pathConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	upChecker := ec.NewProcessUprobeChecker("UPROBE_BINARIES_MATCH").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(testBinary))).
		WithSymbol(sm.Full("test_2+14"))
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

	cmd := exec.Command(testBinary, "2", num)
	require.NoError(t, cmd.Run())
	require.Equal(t, 0, cmd.ProcessState.ExitCode())

	err = jsonchecker.JsonTestCheck(t, checker)
	require.NoError(t, err)
}

func TestUprobeOverrideRegsAction_8bytes(t *testing.T) {
	testUprobeOverrideRegsActionSize(t, "rax=0x1234567887654321", "0x1234567887654321")
}

func TestUprobeOverrideRegsAction_4bytes(t *testing.T) {
	testUprobeOverrideRegsActionSize(t, "eax=0x12345678", "0xdeadbeef12345678")
}

func TestUprobeOverrideRegsAction_2bytes(t *testing.T) {
	testUprobeOverrideRegsActionSize(t, "ax=0x1234", "0xdeadbeefdead1234")
}

func TestUprobeOverrideRegsAction_1byte(t *testing.T) {
	testUprobeOverrideRegsActionSize(t, "al=0x12", "0xdeadbeefdeadbe12")
}

func TestUprobePtRegsData(t *testing.T) {
	testBinary := testutils.RepoRootPath("contrib/tester-progs/regs-override")

	// Put uprobe in test_1 function at:
	//
	//     "push   %rbp\n"         /* +0  55             */
	//     "mov    %rsp,%rbp\n"    /* +1  48 89 e5       */
	//     "mov    $0x1,%eax\n"    /* +4  b8 01 00 00 00 */
	// --> "mov    $0x3,%eax\n"    /* +9  b8 03 00 00 00 */
	//     "pop    %rbp\n"         /* +14 5d             */
	//     "ret\n"                 /* +15 c3             */
	//
	// Make sure we retrieve data with eax value (1) as int argument.

	pathHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe"
spec:
  uprobes:
  - path: "` + testBinary + `"
    symbols:
    - "test_1+14"
    data:
    - index: 0
      type: "int"
      source: "pt_regs"
      resolve: "eax"
`

	pathConfigHook := []byte(pathHook)
	err := os.WriteFile(testConfigFile, pathConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	upChecker := ec.NewProcessUprobeChecker("UPROBE_DATA_MATCH").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(testBinary))).
		WithSymbol(sm.Full("test_1+14")).
		WithData(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(3),
			))

	checker := ec.NewUnorderedEventChecker(upChecker)

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	cmd := exec.Command(testBinary, "1")
	require.Error(t, cmd.Run())
	require.Equal(t, 3, cmd.ProcessState.ExitCode())

	err = jsonchecker.JsonTestCheck(t, checker)
	require.NoError(t, err)
}

func testUprobePtRegsMatch(t *testing.T, value int, expectFail bool) {
	testBinary := testutils.RepoRootPath("contrib/tester-progs/regs-override")

	// Put uprobe in test_1 function at:
	//
	//     "push   %rbp\n"         /* +0  55             */
	//     "mov    %rsp,%rbp\n"    /* +1  48 89 e5       */
	// --> "mov    $0x1,%eax\n"    /* +4  b8 01 00 00 00 */
	//     "mov    $0x3,%eax\n"    /* +9  b8 03 00 00 00 */
	//     "pop    %rbp\n"         /* +14 5d             */
	//     "ret\n"                 /* +15 c3             */
	//
	// Make sure we retrieve data with eax value (1) as int argument
	// and match the expected value via matchData.

	pathHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe"
spec:
  uprobes:
  - path: "` + testBinary + `"
    symbols:
    - "test_1+9"
    data:
    - index: 0
      type: "int"
      source: "pt_regs"
      resolve: "eax"
    selectors:
    - matchData:
      - index: 0
        operator: "Equal"
        values:
        - "` + strconv.Itoa(value) + `"
`

	pathConfigHook := []byte(pathHook)
	err := os.WriteFile(testConfigFile, pathConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	upChecker := ec.NewProcessUprobeChecker("UPROBE_DATA_MATCH").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(testBinary))).
		WithSymbol(sm.Full("test_1+9")).
		WithData(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(int32(value)),
			))

	checker := ec.NewUnorderedEventChecker(upChecker)

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	cmd := exec.Command(testBinary, "1")
	require.Error(t, cmd.Run())
	require.Equal(t, 3, cmd.ProcessState.ExitCode())

	err = jsonchecker.JsonTestCheckExpect(t, checker, expectFail)
	require.NoError(t, err)
}

func TestUprobePtRegsDataMatch(t *testing.T) {
	testUprobePtRegsMatch(t, 1, false)
}

func TestUprobePtRegsDataNotMatch(t *testing.T) {
	testUprobePtRegsMatch(t, 10, true)
}
