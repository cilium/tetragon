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

	var symbol string

	pathHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe"
spec:
  uprobes:
  - path: "` + testBinary + `"
`
	switch runtime.GOARCH {
	case "amd64":
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
		symbol = "test_1+9"
		pathHook += `
    symbols:
    - "` + symbol + `"
    selectors:
    - matchActions:
      - action: Override
        argRegs:
        - "rax=11"
        - "rbp=(%rsp)"
        - "rip=8(%rsp)"
        - "rsp=8%rsp"
`
	case "arm64":
		//   a9bf7bfd        stp     x29, x30, [sp, #-16]!
		//   910003fd        mov     x29, sp
		//   52800020        mov     w0, #0x1                        // #1
		//   52800060   -->  mov     w0, #0x3                        // #3
		//   a8c17bfd        ldp     x29, x30, [sp], #16
		//   d65f03c0        ret
		symbol = "test_1+12"
		pathHook += `
    symbols:
    - "` + symbol + `"
    selectors:
    - matchActions:
      - action: Override
        argRegs:
        - "w0=11"
        - "x29=(%sp)"
        - "pc=8(%sp)"
        - "sp=16%sp"
`
	}

	pathConfigHook := []byte(pathHook)
	err := os.WriteFile(testConfigFile, pathConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	upChecker := ec.NewProcessUprobeChecker("UPROBE_BINARIES_MATCH").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(testBinary))).
		WithSymbol(sm.Full(symbol))
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
		field     string
		kpArgs    []*ec.KprobeArgumentChecker
	}{
		{"uint64", 10, "v64", []*ec.KprobeArgumentChecker{
			ec.NewKprobeArgumentChecker().WithSizeArg(10), // uint64(10)
			ec.NewKprobeArgumentChecker().WithUintArg(0),
			ec.NewKprobeArgumentChecker().WithUintArg(0),
			ec.NewKprobeArgumentChecker().WithErrorArg(ec.NewKprobeErrorChecker().WithMessage(sm.Full("3"))),
			ec.NewKprobeArgumentChecker().WithErrorArg(ec.NewKprobeErrorChecker().WithMessage(sm.Full("2"))),
		}},
		{"uint32", 11, "v32", []*ec.KprobeArgumentChecker{
			ec.NewKprobeArgumentChecker().WithSizeArg(0),
			ec.NewKprobeArgumentChecker().WithUintArg(11), // uint32(11)
			ec.NewKprobeArgumentChecker().WithUintArg(0),
			ec.NewKprobeArgumentChecker().WithErrorArg(ec.NewKprobeErrorChecker().WithMessage(sm.Full("3"))),
			ec.NewKprobeArgumentChecker().WithErrorArg(ec.NewKprobeErrorChecker().WithMessage(sm.Full("2"))),
		}},
		{"uint32", 12, "sub.v32", []*ec.KprobeArgumentChecker{
			ec.NewKprobeArgumentChecker().WithSizeArg(0),
			ec.NewKprobeArgumentChecker().WithUintArg(0),
			ec.NewKprobeArgumentChecker().WithUintArg(12), // uint32(12)
			ec.NewKprobeArgumentChecker().WithErrorArg(ec.NewKprobeErrorChecker().WithMessage(sm.Full("3"))),
			ec.NewKprobeArgumentChecker().WithErrorArg(ec.NewKprobeErrorChecker().WithMessage(sm.Full("2"))),
		}},
		{"uint64", 13, "arr[2].v64", []*ec.KprobeArgumentChecker{
			ec.NewKprobeArgumentChecker().WithSizeArg(0),
			ec.NewKprobeArgumentChecker().WithUintArg(0),
			ec.NewKprobeArgumentChecker().WithUintArg(0),
			ec.NewKprobeArgumentChecker().WithSizeArg(13), // uint64(13)
			ec.NewKprobeArgumentChecker().WithErrorArg(ec.NewKprobeErrorChecker().WithMessage(sm.Full("3"))),
		}},
		{"uint64", 14, "dyn[6].v64", []*ec.KprobeArgumentChecker{
			ec.NewKprobeArgumentChecker().WithSizeArg(0),
			ec.NewKprobeArgumentChecker().WithUintArg(0),
			ec.NewKprobeArgumentChecker().WithUintArg(0),
			ec.NewKprobeArgumentChecker().WithErrorArg(ec.NewKprobeErrorChecker().WithMessage(sm.Full("3"))),
			ec.NewKprobeArgumentChecker().WithSizeArg(14), // uint64(14)
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
    - index: 1
      type: "` + tt[3].specTy + `"
      btfType: "mystruct"
      resolve: "` + tt[3].field + `"
    - index: 1
      type: "` + tt[4].specTy + `"
      btfType: "mystruct"
      resolve: "` + tt[4].field + `"
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

func TestUprobeResolvePageFault(t *testing.T) {
	if !config.EnableLargeProgs() || !bpf.HasUprobeRefCtrOffset() {
		t.Skip("Need 5.3 or newer kernel for uprobe ref_ctr_off support for this test.")
	}

	if !bpf.HasKfunc("bpf_copy_from_user_str") {
		t.Skip("this test requires bpf_copy_from_user_str kfunc support")
	}

	uprobe := testutils.RepoRootPath("contrib/tester-progs/uprobe-resolve")
	uprobeBtf := testutils.RepoRootPath("contrib/tester-progs/uprobe-resolve.btf")

	tt := []struct {
		specTy    string
		filterVal string
		field     string
		kpArgs    []*ec.KprobeArgumentChecker
	}{
		{"string", "hello world!", "subp.buff", []*ec.KprobeArgumentChecker{
			ec.NewKprobeArgumentChecker().WithStringArg(sm.Full("hello world!")),
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
    - index: 1
      type: "` + tt[0].specTy + `"
      btfType: "mystruct"
      resolve: "` + tt[0].field + `"
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
					sm.Full(tt[i].field+" \""+tt[i].filterVal+"\""),
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
		cmd := exec.Command(uprobe, tt[i].field, tt[i].filterVal)
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

	var symbol string

	switch runtime.GOARCH {
	case "amd64":

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
		symbol = "test_2+14"
	case "arm64":
		//   a9bf7bfd        stp     x29, x30, [sp, #-16]!
		//   910003fd        mov     x29, sp
		//   58000640        ldr     x0, 8d0 <main+0xbc>
		//   a8c17bfd -->    ldp     x29, x30, [sp], #16
		//   d65f03c0        ret
		symbol = "test_2+12"
	}

	pathHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe"
spec:
  uprobes:
  - path: "` + testBinary + `"
    symbols:
    - "` + symbol + `"
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
		WithSymbol(sm.Full(symbol))
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
	switch runtime.GOARCH {
	case "amd64":
		testUprobeOverrideRegsActionSize(t, "rax=0x1234567887654321", "0x1234567887654321")
	case "arm64":
		testUprobeOverrideRegsActionSize(t, "x0=0x1234567887654321", "0x1234567887654321")
	}
}

func TestUprobeOverrideRegsAction_4bytes(t *testing.T) {
	switch runtime.GOARCH {
	case "amd64":
		testUprobeOverrideRegsActionSize(t, "eax=0x12345678", "0xdeadbeef12345678")
	case "arm64":
		testUprobeOverrideRegsActionSize(t, "w0=0x12345678", "0xdeadbeef12345678")
	}
}

func TestUprobeOverrideRegsAction_2bytes(t *testing.T) {
	switch runtime.GOARCH {
	case "amd64":
		testUprobeOverrideRegsActionSize(t, "ax=0x1234", "0xdeadbeefdead1234")
	default:
		t.Skip("arm64 doesn't have 2 byte registers")
	}
}

func TestUprobeOverrideRegsAction_1byte(t *testing.T) {
	switch runtime.GOARCH {
	case "amd64":
		testUprobeOverrideRegsActionSize(t, "al=0x12", "0xdeadbeefdeadbe12")
	default:
		t.Skip("arm64 doesn't have 1 byte registers")
	}
}

func TestUprobePtRegsData(t *testing.T) {
	testBinary := testutils.RepoRootPath("contrib/tester-progs/regs-override")

	pathHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe"
spec:
  uprobes:
  - path: "` + testBinary + `"`

	var symbol string

	switch runtime.GOARCH {
	case "amd64":
		// Put uprobe in test_1 function at:
		//
		//     "push   %rbp\n"         /* +0  55             */
		//     "mov    %rsp,%rbp\n"    /* +1  48 89 e5       */
		//     "mov    $0x1,%eax\n"    /* +4  b8 01 00 00 00 */
		// --> "mov    $0x3,%eax\n"    /* +9  b8 03 00 00 00 */
		//     "pop    %rbp\n"         /* +14 5d             */
		//     "ret\n"                 /* +15 c3             */
		//
		// Make sure we retrieve data with eax value (3) as int argument.
		symbol = "test_1+14"
		pathHook += `
    symbols:
    - "` + symbol + `"
    data:
    - index: 0
      type: "int"
      source: "pt_regs"
      resolve: "eax"`
	case "arm64":
		// Put uprobe in test_1 function at:
		//
		//   a9bf7bfd        stp     x29, x30, [sp, #-16]!
		//   910003fd        mov     x29, sp
		//   52800020        mov     w0, #0x1                        // #1
		//   52800060   -->  mov     w0, #0x3                        // #3
		//   a8c17bfd        ldp     x29, x30, [sp], #16
		//   d65f03c0        ret
		// Make sure we retrieve data with w0 value (3) as int argument.
		symbol = "test_1+16"
		pathHook += `
    symbols:
    - "` + symbol + `"
    data:
    - index: 0
      type: "int"
      source: "pt_regs"
      resolve: "w0"`
	}

	pathConfigHook := []byte(pathHook)
	err := os.WriteFile(testConfigFile, pathConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	upChecker := ec.NewProcessUprobeChecker("UPROBE_DATA_MATCH").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(testBinary))).
		WithSymbol(sm.Full(symbol)).
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

	pathHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe"
spec:
  uprobes:
  - path: "` + testBinary + `"`

	var symbol string

	switch runtime.GOARCH {
	case "amd64":
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
		symbol = "test_1+9"
		pathHook += `
    symbols:
    - "` + symbol + `"
    data:
    - index: 1 # config validation currently requires specifying index for the data section, but the value is meaningless and unused
      type: "int"
      source: "pt_regs"
      resolve: "eax"
    selectors:
    - matchData:
      - index: 0
        operator: "Equal"
        values:
        - "` + strconv.Itoa(value) + `"`
	case "arm64":
		// Put uprobe in test_1 function at:
		//
		//   a9bf7bfd        stp     x29, x30, [sp, #-16]!
		//   910003fd        mov     x29, sp
		//   52800020   -->  mov     w0, #0x1                        // #1
		//   52800060        mov     w0, #0x3                        // #3
		//   a8c17bfd        ldp     x29, x30, [sp], #16
		//   d65f03c0        ret
		// Make sure we retrieve data with w0 value (1) as int argument.
		// and match the expected value via matchData.
		symbol = "test_1+12"
		pathHook += `
    symbols:
    - "` + symbol + `"
    data:
    - index: 1 # config validation currently requires specifying index for the data section, but the value is meaningless and unused
      type: "int"
      source: "pt_regs"
      resolve: "w0"
    selectors:
    - matchData:
      - index: 0
        operator: "Equal"
        values:
        - "` + strconv.Itoa(value) + `"`
	}

	pathConfigHook := []byte(pathHook)
	err := os.WriteFile(testConfigFile, pathConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	upChecker := ec.NewProcessUprobeChecker("UPROBE_DATA_MATCH").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(testBinary))).
		WithSymbol(sm.Full(symbol)).
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

func testUprobePtRegsPreload(t *testing.T, multi bool) {
	if !bpf.HasKfunc("bpf_copy_from_user_str") {
		t.Skip("skipping")
	}

	testBinary := testutils.RepoRootPath("contrib/tester-progs/regs-override")

	disableUprobeMulti := ""

	if !multi {
		disableUprobeMulti = `
  options:
    - name: "disable-uprobe-multi"
      value: "1"`
	}

	// Put uprobe in test_3 function at:
	//
	//      static const char *test_3_string = "test_3_string_CASE";
	//
	//      "push   %%rbp\n"          /* +0  55                            */
	//      "mov    %%rsp, %%rbp\n"   /* +1  48 89 e5                      */
	//      "mov    %[str], %%rdi\n"  /* +4  48 8b 3d 96 2e 00 00          */
	//      "pop    %%rbp\n"          /* +11 5d                            */
	// -->  "mov    $0x0,%%rax\n"     /* +12 48 c7 c0 00 00 00 00          */
	//      "mov    $0xff,%%rax\n"    /* +19 48 c7 c0 ff 00 00 00          */
	//      "ret\n"                   /* +26 c3                            */
	//      :
	//      : [str] "m" (test_3_string)
	//
	// Make sure we retrieve data with eax value (1) as int argument
	// and match the expected value via matchData.

	pathHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe"
spec: ` + disableUprobeMulti + `
  uprobes:
  - path: "` + testBinary + `"
    symbols:
    - "test_3+12"
    data:
    - index: 0
      type: "string"
      source: "pt_regs"
      resolve: "rdi"
`

	pathConfigHook := []byte(pathHook)
	err := os.WriteFile(testConfigFile, pathConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	upChecker := ec.NewProcessUprobeChecker("UPROBE_DATA_MATCH").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(testBinary))).
		WithSymbol(sm.Full("test_3+12")).
		WithData(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithStringArg(sm.Full("test_3_string_CASE")),
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

	cmd := exec.Command(testBinary, "3")
	require.Error(t, cmd.Run())
	require.Equal(t, 255, cmd.ProcessState.ExitCode())

	err = jsonchecker.JsonTestCheck(t, checker)
	require.NoError(t, err)
}

func TestUprobePtRegsPreload(t *testing.T) {
	testUprobePtRegsPreload(t, false)
}

func TestUprobePtRegsPreloadMulti(t *testing.T) {
	if !bpf.HasUprobeMulti() {
		t.Skip("skipping preload test for uprobe multi, it is not supported in kernel")
	}

	testUprobePtRegsPreload(t, true)
}

func testUprobePtRegsPreloadDouble(t *testing.T, multi bool) {
	if !bpf.HasKfunc("bpf_copy_from_user_str") {
		t.Skip("skipping")
	}

	testBinary := testutils.RepoRootPath("contrib/tester-progs/regs-override")

	disableUprobeMulti := ""

	if !multi {
		disableUprobeMulti = `
  options:
    - name: "disable-uprobe-multi"
      value: "1"`
	}

	// Put uprobe in test_3 function at:
	//
	//      static const char *test_3_string = "test_3_string_CASE";
	//
	//      "push   %%rbp\n"          /* +0  55                            */
	//      "mov    %%rsp, %%rbp\n"   /* +1  48 89 e5                      */
	//      "mov    %[str], %%rdi\n"  /* +4  48 8b 3d 96 2e 00 00          */
	//      "pop    %%rbp\n"          /* +11 5d                            */
	// -->  "mov    $0x0,%%rax\n"     /* +12 48 c7 c0 00 00 00 00          */
	//      "mov    $0xff,%%rax\n"    /* +19 48 c7 c0 ff 00 00 00          */
	//      "ret\n"                   /* +26 c3                            */
	//      :
	//      : [str] "m" (test_3_string)
	//
	// Make sure we retrieve data with eax value (1) as int argument
	// and match the expected value via matchData.
	//
	// This test does the same thing as testUprobePtRegsPreload but instead
	// of single uprobe with preload argument it adds two uprobes with preload
	// argument.

	pathHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe"
spec: ` + disableUprobeMulti + `
  uprobes:
  - path: "` + testBinary + `"
    symbols:
    - "test_3+12"
    data:
    - index: 0
      type: "string"
      source: "pt_regs"
      resolve: "rdi"
  - path: "` + testBinary + `"
    symbols:
    - "test_3+12"
    data:
    - index: 0
      type: "string"
      source: "pt_regs"
      resolve: "rdi"
`

	pathConfigHook := []byte(pathHook)
	err := os.WriteFile(testConfigFile, pathConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	upChecker := ec.NewProcessUprobeChecker("UPROBE_DATA_MATCH").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(testBinary))).
		WithSymbol(sm.Full("test_3+12")).
		WithData(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithStringArg(sm.Full("test_3_string_CASE")),
			))

	checker := ec.NewUnorderedEventChecker(upChecker, upChecker)

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

	cmd := exec.Command(testBinary, "3")
	require.Error(t, cmd.Run())
	require.Equal(t, 255, cmd.ProcessState.ExitCode())

	err = jsonchecker.JsonTestCheck(t, checker)
	require.NoError(t, err)
}

func TestUprobePtRegsPreloadDouble(t *testing.T) {
	testUprobePtRegsPreloadDouble(t, false)
}

func TestUprobePtRegsPreloadDoubleMulti(t *testing.T) {
	testUprobePtRegsPreloadDouble(t, true)
}

func testUprobePtRegsPreloadSubstring(t *testing.T, str string, ignoreCase bool, fail, single bool) {
	if !bpf.HasKfunc("bpf_copy_from_user_str") {
		t.Skip("skipping, no string preload support")
	}
	if ignoreCase {
		if !bpf.HasKfunc("bpf_strncasestr") {
			t.Skip("skipping, can't use SubStringIgnCase operator, no kernel support")
		}
	} else {
		if !bpf.HasKfunc("bpf_strnstr") {
			t.Skip("skipping, can't use SubString operator, no kernel support")
		}
	}
	if !single && !bpf.HasUprobeMulti() {
		t.Skip("skipping, can't use uprobe multi, no kernel support")
	}

	testBinary := testutils.RepoRootPath("contrib/tester-progs/regs-override")

	op := "SubString"
	if ignoreCase {
		op = "SubStringIgnCase"
	}

	options := ""
	if single {
		options = `  options:
  - name: "disable-uprobe-multi"
    value: "1"`
	}

	// Put uprobe in test_3 function at:
	//
	//      static const char *test_3_string = "test_3_string";
	//
	//      "push   %%rbp\n"          /* +0  55                            */
	//      "mov    %%rsp, %%rbp\n"   /* +1  48 89 e5                      */
	//      "mov    %[str], %%rdi\n"  /* +4  48 8b 3d 96 2e 00 00          */
	//      "pop    %%rbp\n"          /* +11 5d                            */
	// -->  "mov    $0x0,%%rax\n"     /* +12 48 c7 c0 00 00 00 00          */
	//      "mov    $0xff,%%rax\n"    /* +19 48 c7 c0 ff 00 00 00          */
	//      "ret\n"                   /* +26 c3                            */
	//      :
	//      : [str] "m" (test_3_string)
	//
	// Make sure we retrieve data with eax value (1) as int argument
	// and match the expected value via matchData.

	pathHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe"
spec:
` + options + `
  uprobes:
  - path: "` + testBinary + `"
    symbols:
    - "test_3+12"
    data:
    - index: 0
      type: "string"
      source: "pt_regs"
      resolve: "rdi"
    selectors:
    - matchData:
      - index: 0
        operator: "` + op + `"
        values:
        - "` + str + `"
`

	pathConfigHook := []byte(pathHook)
	err := os.WriteFile(testConfigFile, pathConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	upChecker := ec.NewProcessUprobeChecker("UPROBE_DATA_MATCH").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(testBinary))).
		WithSymbol(sm.Full("test_3+12")).
		WithData(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithStringArg(sm.Full("test_3_string_CASE")),
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

	cmd := exec.Command(testBinary, "3")
	require.Error(t, cmd.Run())
	require.Equal(t, 255, cmd.ProcessState.ExitCode())

	err = jsonchecker.JsonTestCheckExpect(t, checker, fail)
	require.NoError(t, err)
}

func TestUprobePtRegsPreloadSubstringMatchSingle(t *testing.T) {
	testUprobePtRegsPreloadSubstring(t,
		"string_CASE",
		false, /* ignore case */
		false, /* fail */
		true,  /* single */
	)
}

// Test substring at the beginning of the string
func TestUprobePtRegsPreloadSubstringMatchSingle2(t *testing.T) {
	testUprobePtRegsPreloadSubstring(t,
		"test_3_string",
		false, /* ignore case */
		false, /* fail */
		true,  /* single */
	)
}

func TestUprobePtRegsPreloadSubstringNotMatchSingle(t *testing.T) {
	testUprobePtRegsPreloadSubstring(t,
		"garbage",
		false, /* ignore case */
		true,  /* fail */
		true,  /* single */
	)
}

func TestUprobePtRegsPreloadSubstringIgnCaseMatchSingle(t *testing.T) {
	testUprobePtRegsPreloadSubstring(t,
		"string_case",
		true,  /* ignore case */
		false, /* fail */
		true,  /* single */
	)
}

func TestUprobePtRegsPreloadSubstringIgnCaseNotMatchSingle(t *testing.T) {
	testUprobePtRegsPreloadSubstring(t,
		"garbage",
		true, /* ignore case */
		true, /* fail */
		true, /* single */
	)
}

func TestUprobePtRegsPreloadSubstringMatch(t *testing.T) {
	testUprobePtRegsPreloadSubstring(t,
		"string_CASE",
		false, /* ignore case */
		false, /* fail */
		false, /* single */
	)
}

func TestUprobePtRegsPreloadSubstringNotMatch(t *testing.T) {
	testUprobePtRegsPreloadSubstring(t,
		"garbage",
		false, /* ignore case */
		true,  /* fail */
		false, /* single */
	)
}

func TestUprobePtRegsPreloadSubstringIgnCaseMatch(t *testing.T) {
	testUprobePtRegsPreloadSubstring(t,
		"string_case",
		true,  /* ignore case */
		false, /* fail */
		false, /* single */
	)
}

func TestUprobePtRegsPreloadSubstringIgnCaseNotMatch(t *testing.T) {
	testUprobePtRegsPreloadSubstring(t,
		"garbage",
		true,  /* ignore case */
		true,  /* fail */
		false, /* single */
	)
}

func testUprobePtRegsPreloadSubstringOverride(t *testing.T, single bool) {
	if !bpf.HasKfunc("bpf_copy_from_user_str") {
		t.Skip("skipping, no string preload support")
	}
	if !bpf.HasUprobeRegsChange() {
		t.Skip("skipping, no regs change support in kernel")
	}
	if !bpf.HasKfunc("bpf_strnstr") {
		t.Skip("skipping, no bpf_strnstr kfunc in kernel")
	}

	testBinary := testutils.RepoRootPath("contrib/tester-progs/regs-override")

	// Put uprobe in test_3 function at:
	//
	//      static const char *test_3_string = "test_3_string";
	//
	//      "push   %%rbp\n"          /* +0  55                            */
	//      "mov    %%rsp, %%rbp\n"   /* +1  48 89 e5                      */
	//      "mov    %[str], %%rdi\n"  /* +4  48 8b 3d 96 2e 00 00          */
	//      "pop    %%rbp\n"          /* +11 5d                            */
	//      "mov    $0x0,%%rax\n"     /* +12 48 c7 c0 00 00 00 00          */
	// -->  "mov    $0xff,%%rax\n"    /* +19 48 c7 c0 ff 00 00 00          */
	//      "ret\n"                   /* +26 c3                            */
	//      :
	//      : [str] "m" (test_3_string)
	//
	// Make sure we retrieve data with eax value (1) as int argument
	// and match the expected value via matchData.

	options := ""
	if single {
		options = `  options:
  - name: "disable-uprobe-multi"
    value: "1"`
	}

	pathHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe"
spec:
` + options + `
  uprobes:
  - path: "` + testBinary + `"
    symbols:
    - "test_3+19"
    data:
    - index: 0
      type: "string"
      source: "pt_regs"
      resolve: "rdi"
    selectors:
    - matchData:
      - index: 0
        operator: "SubString"
        values:
        - "_3_"
      matchActions:
      - action: Override
        argRegs:
        - "rip=7%rip"
`

	pathConfigHook := []byte(pathHook)
	err := os.WriteFile(testConfigFile, pathConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	upChecker := ec.NewProcessUprobeChecker("UPROBE_DATA_MATCH").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(testBinary))).
		WithSymbol(sm.Full("test_3+19")).
		WithData(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithStringArg(sm.Full("test_3_string_CASE")),
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

	cmd := exec.Command(testBinary, "3")
	require.NoError(t, cmd.Run())
	require.Equal(t, 0, cmd.ProcessState.ExitCode())

	err = jsonchecker.JsonTestCheck(t, checker)
	require.NoError(t, err)
}

func TestUprobePtRegsPreloadSubstringOverrideSingle(t *testing.T) {
	testUprobePtRegsPreloadSubstringOverride(t, true)
}

func TestUprobePtRegsPreloadSubstringOverrideMulti(t *testing.T) {
	testUprobePtRegsPreloadSubstringOverride(t, false)
}

func TestUprobeResolveNull(t *testing.T) {
	if !config.EnableLargeProgs() || !bpf.HasUprobeRefCtrOffset() {
		t.Skip("Need 5.3 or newer kernel for uprobe ref_ctr_off support for this test.")
	}

	uprobe := testutils.RepoRootPath("contrib/tester-progs/uprobe-null")
	uprobeBtf := testutils.RepoRootPath("contrib/tester-progs/uprobe-null.btf")

	tt := []struct {
		arg    string
		kpArgs []*ec.KprobeArgumentChecker
	}{
		{"first", []*ec.KprobeArgumentChecker{
			ec.NewKprobeArgumentChecker().WithErrorArg(ec.NewKprobeErrorChecker().WithMessage(sm.Full("1"))),
		}},
		{"second", []*ec.KprobeArgumentChecker{
			ec.NewKprobeArgumentChecker().WithErrorArg(ec.NewKprobeErrorChecker().WithMessage(sm.Full("2"))),
		}},
		{"third", []*ec.KprobeArgumentChecker{
			ec.NewKprobeArgumentChecker().WithErrorArg(ec.NewKprobeErrorChecker().WithMessage(sm.Full("3"))),
		}},
		{"nonull", []*ec.KprobeArgumentChecker{
			ec.NewKprobeArgumentChecker().WithIntArg(0),
		}},
	}

	uprobeHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe-null"
spec:
  uprobes:
  - path: "` + uprobe + `"
    btfPath: "` + uprobeBtf + `"
    symbols:
    - "func"
    args:
    - index: 0
      type: "int32"
      btfType: "first"
      resolve: "second.third.val"
`

	uprobeConfigHook := []byte(uprobeHook)
	err := os.WriteFile(testConfigFile, uprobeConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	var checkers []ec.EventChecker
	for i := range tt {
		checkers = append(checkers, ec.NewProcessUprobeChecker("uprobe-null").
			WithProcess(ec.NewProcessChecker().
				WithBinary(sm.Full(uprobe)).
				WithArguments(
					sm.Full(tt[i].arg)),
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
		cmd := exec.Command(uprobe, tt[i].arg)
		cmdErr := testutils.RunCmdAndLogOutput(t, cmd)
		require.NoError(t, cmdErr)
	}

	err = jsonchecker.JsonTestCheck(t, ec.NewUnorderedEventChecker(checkers...))
	require.NoError(t, err)
}

func UprobeResolveNullMatch(t *testing.T, expectCheckerFailure bool, arg string) {
	if !config.EnableLargeProgs() || !bpf.HasUprobeRefCtrOffset() {
		t.Skip("Need 5.3 or newer kernel for uprobe ref_ctr_off support for this test.")
	}

	uprobe := testutils.RepoRootPath("contrib/tester-progs/uprobe-null")
	uprobeBtf := testutils.RepoRootPath("contrib/tester-progs/uprobe-null.btf")

	uprobeHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe-null"
spec:
  uprobes:
  - path: "` + uprobe + `"
    btfPath: "` + uprobeBtf + `"
    symbols:
    - "func"
    args:
    - index: 0
      type: "int32"
      btfType: "first"
      resolve: "second.third.val"
    selectors:
    - matchArgs:
      - args: [0]
        operator: "Equal"
        values:
          - "0"
`

	uprobeConfigHook := []byte(uprobeHook)
	err := os.WriteFile(testConfigFile, uprobeConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	kpArgs := []*ec.KprobeArgumentChecker{
		ec.NewKprobeArgumentChecker(),
	}

	var checkers []ec.EventChecker
	checkers = append(checkers, ec.NewProcessUprobeChecker("uprobe-null").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(uprobe)).
			WithArguments(
				sm.Full(arg)),
		).WithArgs(ec.NewKprobeArgumentListMatcher().
		WithOperator(lc.Ordered).
		WithValues(kpArgs...)))

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

	cmd := exec.Command(uprobe, arg)
	cmdErr := testutils.RunCmdAndLogOutput(t, cmd)
	require.NoError(t, cmdErr)

	err = jsonchecker.JsonTestCheckExpect(t, ec.NewUnorderedEventChecker(checkers...), expectCheckerFailure)
	require.NoError(t, err)
}

func TestUprobeResolveNullMatchPositive(t *testing.T) {
	UprobeResolveNullMatch(t, false, "nonull")
}

func TestUprobeResolveNullMatchNegative(t *testing.T) {
	UprobeResolveNullMatch(t, true, "first")
}
