// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build amd64 && linux

package tracing

import (
	"context"
	"os"
	"os/exec"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/jsonchecker"
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
