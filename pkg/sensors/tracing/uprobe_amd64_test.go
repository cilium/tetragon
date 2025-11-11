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

type TestInvocation struct {
	specTy  string
	arg1    string
	arg2    string
	resolve string
	kpArgs  []*ec.KprobeArgumentChecker
}

func get_checker(ti TestInvocation, binary_name string) *ec.ProcessUprobeChecker {
	return ec.NewProcessUprobeChecker("uprobe-resolve").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(binary_name)).
			WithArguments(
				sm.Full(ti.arg1 + " " + ti.arg2),
			),
		).WithArgs(ec.NewKprobeArgumentListMatcher().
		WithOperator(lc.Ordered).
		WithValues(ti.kpArgs...))
}

func RunResolveTest(t *testing.T, tt []TestInvocation, expect_failure bool, selectors string) {
	if !config.EnableLargeProgs() || !bpf.HasUprobeRefCtrOffset() {
		t.Skip("Need 5.3 or newer kernel for uprobe ref_ctr_off support for this test.")
	}

	if !bpf.HasProbeWriteUserHelper() {
		t.Skip("need bpf_probe_write_user() for this test")
	}

	uprobe := testutils.RepoRootPath("contrib/tester-progs/uprobe-resolve")
	uprobeBtf := testutils.RepoRootPath("contrib/tester-progs/uprobe-resolve.btf")

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
      type: "int32"`

	for _, ti := range tt {
		uprobeHook = uprobeHook + `
    - index: 1
      type: "` + ti.specTy + `"
      btfType: "mystruct"
      resolve: "` + ti.resolve + `"`
	}

	uprobeHook = uprobeHook + selectors

	uprobeConfigHook := []byte(uprobeHook)
	err := os.WriteFile(testConfigFile, uprobeConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	var checkers []ec.EventChecker
	for _, ti := range tt {
		checkers = append(checkers, get_checker(ti, uprobe))
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

	for _, ti := range tt {
		cmd := exec.Command(uprobe, ti.arg1, ti.arg2)
		cmdErr := testutils.RunCmdAndLogOutput(t, cmd)
		require.NoError(t, cmdErr)
	}

	err = jsonchecker.JsonTestCheckExpect(t, ec.NewUnorderedEventChecker(checkers...), expect_failure)
	require.NoError(t, err)
}

func TestUprobeResolve(t *testing.T) {
	tt := []TestInvocation{
		{"uint64", "v64", "10", "v64", []*ec.KprobeArgumentChecker{
			ec.NewKprobeArgumentChecker().WithIntArg(0).WithResolveErrDepth(0),
			ec.NewKprobeArgumentChecker().WithSizeArg(10).WithResolveErrDepth(0), // uint64(10)
			ec.NewKprobeArgumentChecker().WithUintArg(0).WithResolveErrDepth(0),
			ec.NewKprobeArgumentChecker().WithUintArg(0).WithResolveErrDepth(0),
		}},
		{"uint32", "v32", "11", "v32", []*ec.KprobeArgumentChecker{
			ec.NewKprobeArgumentChecker().WithIntArg(0).WithResolveErrDepth(0),
			ec.NewKprobeArgumentChecker().WithSizeArg(0).WithResolveErrDepth(0),
			ec.NewKprobeArgumentChecker().WithUintArg(11).WithResolveErrDepth(0), // uint32(11)
			ec.NewKprobeArgumentChecker().WithUintArg(0).WithResolveErrDepth(0),
		}},
		{"uint32", "sub.v32", "12", "sub.v32", []*ec.KprobeArgumentChecker{
			ec.NewKprobeArgumentChecker().WithIntArg(0).WithResolveErrDepth(0),
			ec.NewKprobeArgumentChecker().WithSizeArg(0).WithResolveErrDepth(0),
			ec.NewKprobeArgumentChecker().WithUintArg(0).WithResolveErrDepth(0),
			ec.NewKprobeArgumentChecker().WithUintArg(12).WithResolveErrDepth(0), // uint32(12)
		}},
	}

	RunResolveTest(t, tt, false, "")
}

func TestUprobeResolveErr(t *testing.T) {
	/* This test confirms that we properly relay dereferencing issues when resolving an arg.
	 * The first invocation of the uprobe-resolve tester program will not be able to resolve the argument
	 * beause the pointer to mystruct is NULL. This resolve derefernce issue occurs at depth 1 as a result.
	 * The second invocation of the uprobe-resolve tester program will not be able to resolve the
	 * the argument because mystruct's subp member is a NULL pointer. As such resolution fails at depth 2.
	 */
	tt := []TestInvocation{
		{"uint8", "null", "7", "v8", []*ec.KprobeArgumentChecker{
			ec.NewKprobeArgumentChecker().WithIntArg(0).WithResolveErrDepth(0),
			ec.NewKprobeArgumentChecker().WithUintArg(0).WithResolveErrDepth(1), // 0, because couldn't resolve at depth 1
			ec.NewKprobeArgumentChecker().WithUintArg(0).WithResolveErrDepth(1), // 0, because couldn't resolve at depth 1
		}},
		{"uint8", "v8", "7", "subp.v8", []*ec.KprobeArgumentChecker{
			ec.NewKprobeArgumentChecker().WithIntArg(0).WithResolveErrDepth(0),
			ec.NewKprobeArgumentChecker().WithUintArg(7).WithResolveErrDepth(0),
			ec.NewKprobeArgumentChecker().WithUintArg(0).WithResolveErrDepth(2),
		}},
	}

	RunResolveTest(t, tt, false, "")
}

func TestUprobeResolveErrMatch(t *testing.T) {
	/* A positive test that we con match on resolved arguments */
	tt := []TestInvocation{
		{"uint8", "v8", "7", "v8", []*ec.KprobeArgumentChecker{
			ec.NewKprobeArgumentChecker().WithIntArg(0).WithResolveErrDepth(0),
			ec.NewKprobeArgumentChecker().WithUintArg(7).WithResolveErrDepth(0), // 0, because couldn't resolve at depth 1
		}},
	}

	selectors := `
    selectors:
      - matchArgs:
        - args: [1]
          operator: "Equal"
          values:
            - "7"`

	RunResolveTest(t, tt, false, selectors)
}

func TestUprobeResolveErrNoMatch(t *testing.T) {
	/* Passing "null" as the first command line parameter to the test program uprobe-resolve make the program to pass NULL as the second parameter to the probed function.
	 * As such, resolving the argument value will fail as a result, but a dummy argument value will still be seen. The dummy argument will probably be 0, and this would cause a
	 * match for the matchArgs selector, if the selector is not aware that resolution failed. This test confirms that the selector will understand that the argument is not resolved,
	 * and as such prevent the event from firing.
	 */
	tt := []TestInvocation{
		{"uint8", "null", "0", "v8", []*ec.KprobeArgumentChecker{
			ec.NewKprobeArgumentChecker(),
			ec.NewKprobeArgumentChecker(),
		}},
	}

	selectors := `
    selectors:
      - matchArgs:
        - args: [1]
          operator: "Equal"
          values:
            - "0"`

	RunResolveTest(t, tt, true, selectors)
}
