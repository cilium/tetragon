// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"context"
	"strconv"
	"sync"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/ftrace"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	lc "github.com/cilium/tetragon/pkg/matchers/listmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/stretchr/testify/assert"
)

func trigger(t *testing.T) {
	ins := asm.Instructions{
		// Return SK_DROP
		asm.LoadImm(asm.R0, 0, asm.DWord),
		asm.Return(),
	}

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:         "test",
		Type:         ebpf.Tracing,
		AttachType:   ebpf.AttachTraceFEntry,
		Instructions: ins,
		License:      "MIT",
		AttachTo:     "bpf_modify_return_test",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()

	opts := ebpf.RunOptions{}
	ret, err := prog.Run(&opts)
	if err != nil {
		t.Fatal(err)
	}

	if ret != 0 {
		t.Fatalf("Expected return value to be 0, got %d", ret)
	}
}

func TestKprobeArgs(t *testing.T) {
	_, err := ftrace.ReadAvailFuncs("bpf_fentry_test1")
	if err != nil {
		t.Skip("Skipping test: could not find bpf_fentry_test1")
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	t.Logf("tester pid=%s\n", pidStr)

	hook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "sys-write"
spec:
  kprobes:
  - call: "bpf_fentry_test1"
    syscall: false
    args:
    - index: 0
      type: "int"
  - call: "bpf_fentry_test2"
    syscall: false
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "uint64"
  - call: "bpf_fentry_test3"
    syscall: false
    args:
    - index: 0
      type: "int8"
    - index: 1
      type: "int"
    - index: 2
      type: "uint64"
  - call: "bpf_fentry_test4"
    syscall: false
    args:
    - index: 0
      type: "uint64"
    - index: 1
      type: "int8"
    - index: 2
      type: "int"
    - index: 3
      type: "uint64"
  - call: "bpf_fentry_test5"
    syscall: false
    args:
    - index: 0
      type: "uint64"
    - index: 1
      type: "uint64"
    - index: 2
      type: "int16"
    - index: 3
      type: "int"
    - index: 4
      type: "uint64"
    selectors:
    - matchPIDs:
      - operator: In
        followForks: true
        isNamespacePID: false
        values:
        - ` + pidStr

	createCrdFile(t, hook)

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	trigger(t)

	check1 := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full("bpf_fentry_test1")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(1),
			))

	check2 := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full("bpf_fentry_test2")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(2),
				ec.NewKprobeArgumentChecker().WithSizeArg(3),
			))

	check3 := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full("bpf_fentry_test3")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(4),
				ec.NewKprobeArgumentChecker().WithIntArg(5),
				ec.NewKprobeArgumentChecker().WithSizeArg(6),
			))

	check4 := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full("bpf_fentry_test4")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithSizeArg(7),
				ec.NewKprobeArgumentChecker().WithIntArg(8),
				ec.NewKprobeArgumentChecker().WithIntArg(9),
				ec.NewKprobeArgumentChecker().WithSizeArg(10),
			))

	check5 := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full("bpf_fentry_test5")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithSizeArg(11),
				ec.NewKprobeArgumentChecker().WithSizeArg(12),
				ec.NewKprobeArgumentChecker().WithIntArg(13),
				ec.NewKprobeArgumentChecker().WithIntArg(14),
				ec.NewKprobeArgumentChecker().WithSizeArg(15),
			))

	checker := ec.NewUnorderedEventChecker(check1, check2, check3, check4, check5)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}
