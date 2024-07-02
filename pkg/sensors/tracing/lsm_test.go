// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"context"
	"os"
	"os/exec"
	"sync"
	"testing"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/kernels"
	lc "github.com/cilium/tetragon/pkg/matchers/listmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/sensors/base"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/stretchr/testify/assert"
)

func TestLSMObjectLoad(t *testing.T) {
	if !bpf.HasLSMPrograms() || !kernels.MinKernelVersion("5.7") {
		t.Skip()
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
	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	configHookRaw := []byte(configHook)
	err := os.WriteFile(testConfigFile, configHookRaw, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}
	_, err = observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	initialSensor := base.GetInitialSensor()
	initialSensor.Load(bpf.MapPrefixPath())
}

func TestLSMOpenFile(t *testing.T) {
	if !bpf.HasLSMPrograms() || !kernels.MinKernelVersion("5.7") {
		t.Skip()
	}
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

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
        - "/usr/bin/cat"
      matchArgs:
      - index: 0
        operator: "Equal"
        values:
        - "/etc/passwd"
`

	configHookRaw := []byte(configHook)
	err := os.WriteFile(testConfigFile, configHookRaw, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}
	lsmChecker := ec.NewProcessLsmChecker("lsm-file-checker").
		WithFunctionName(sm.Suffix("file_open")).
		WithProcess(ec.NewProcessChecker().WithBinary(sm.Full("/usr/bin/cat"))).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithFileArg(ec.NewKprobeFileChecker().WithPath(sm.Full("/etc/passwd")))))
	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	catCmd := exec.Command("/usr/bin/cat", "/etc/passwd")

	if err := catCmd.Run(); err != nil {
		t.Fatalf("failed to run %s: %s", catCmd, err)
	}

	err = jsonchecker.JsonTestCheck(t, ec.NewUnorderedEventChecker(lsmChecker))
	assert.NoError(t, err)
}
