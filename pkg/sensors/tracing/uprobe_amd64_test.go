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
