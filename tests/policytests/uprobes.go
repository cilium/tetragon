// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tests

import (
	"fmt"
	"math"
	"runtime"
	"strconv"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/bpf"
	telf "github.com/cilium/tetragon/pkg/elf"
	lc "github.com/cilium/tetragon/pkg/matchers/listmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/testutils/policytest"
)

func uprobeSetArgIndex() int {
	if runtime.GOARCH == "arm64" {
		return 7
	}
	return 5
}

// uprobe-pclntab: attach to stripped Go binary via pclntab symbol resolution
var _ = policytest.NewBuilder("uprobe-pclntab").WithLabels("uprobes").WithPolicyTemplate(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe-pclntab"
spec:
  uprobes:
  - path: {{ testBinary "pclntab-stripped" }}
    symbols:
    - "main.main"
    selectors:
    - matchActions:
      - action: Post
`).AddScenario(func(c *policytest.Conf) *policytest.Scenario {
	bin := c.TestBinary("pclntab-stripped")
	upChecker := ec.NewProcessUprobeChecker("UPROBE_PCLNTAB").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(bin))).
		WithSymbol(sm.Full("main.main"))
	return &policytest.Scenario{
		Name:         "execute stripped Go binary, verify uprobe via pclntab",
		Trigger:      policytest.NewCmdTrigger(bin),
		EventChecker: ec.NewUnorderedEventChecker(upChecker),
	}
}).RegisterAtInit()

var _ = policytest.NewBuilder("uprobe-generic").WithLabels("uprobes").WithPolicyTemplate(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe-generic"
spec:
  uprobes:
  - path: {{ testBinary "nop" }}
    symbols:
    - "main"
`).AddScenario(func(c *policytest.Conf) *policytest.Scenario {
	nop := c.TestBinary("nop")
	upChecker := ec.NewProcessUprobeChecker("UPROBE_GENERIC").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(nop))).
		WithSymbol(sm.Full("main"))
	return &policytest.Scenario{
		Name:         "execute nop and check events",
		Trigger:      policytest.NewCmdTrigger(nop),
		EventChecker: ec.NewUnorderedEventChecker(upChecker),
	}
}).RegisterAtInit()

var _ = policytest.NewBuilder("uprobe-override").WithLabels("uprobes").WithPolicyTemplate(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe-override"
spec:
  uprobes:
  - path: {{ testBinary "uprobe-simple" }}
    symbols:
    - "pizza"
    selectors:
    - matchActions:
      - action: Override
        argError: 42
`).WithSkip(func(si *policytest.SkipInfo) string {
	// skip if uprobe_regs_change is not supported
	if !si.AgentInfo.Probes[bpf.UprobeRegsChangeProbe] {
		return "uprobes cannot change registers"
	}
	return ""
}).AddScenario(func(c *policytest.Conf) *policytest.Scenario {
	myBin := c.TestBinary("uprobe-simple")
	upChecker := ec.NewProcessUprobeChecker("uprobe-override").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(myBin))).
		WithSymbol(sm.Full("pizza"))

	exitCode := 42
	if c.TestConf != nil && c.TestConf.MonitorMode {
		exitCode = 0
	}
	postCnt := uint64(1)
	overrideCount := uint64(1)
	return &policytest.Scenario{
		Name:         "execute uprobe-simple, check enforcement and events",
		Trigger:      policytest.NewCmdTrigger(myBin).ExpectExitCode(exitCode),
		EventChecker: ec.NewUnorderedEventChecker(upChecker),
		ActCountChecker: policytest.ActionCounts{
			Post:     &postCnt,
			Override: &overrideCount,
		},
	}
}).RegisterAtInit()

var _ = policytest.NewBuilder("cel-multi-uprobe-one-match").WithLabels("uprobes").WithPolicyTemplate(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "cel-multi-uprobe"
spec:
  uprobes:
  - path: {{ testBinary "libuprobe.so" }}
    symbols:
    - "uprobe_test_lib_arg1"
    selectors:
    - matchArgs:
      - operator: CelExpr
        values:
        - "false"
  - path: {{ testBinary "libuprobe.so" }}
    symbols:
    - "uprobe_test_lib_arg2"
    selectors:
    - matchArgs:
      - operator: CelExpr
        values:
        - "true"
`).WithSkip(func(si *policytest.SkipInfo) string {
	if !si.AgentInfo.Probes[bpf.LargeProgsProbe] {
		return "need 5.3 or newer kernel"
	}

	if !si.AgentInfo.Probes[bpf.UprobeRefCtrOffsetProbe] {
		return "need uprobe ref_ctr_off support"
	}

	if !si.AgentInfo.Probes[bpf.MixBPFAndTailCallsProbe] {
		return "need kernel where we can mix bpf and tail calls"
	}

	return ""
}).AddScenario(func(c *policytest.Conf) *policytest.Scenario {
	myBin := c.TestBinary("uprobe-test-1")
	upChecker := ec.NewProcessUprobeChecker("cel-multi-uprobe").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(myBin))).WithSymbol(sm.Full("uprobe_test_lib_arg2"))

	return &policytest.Scenario{
		Name:         "check uprobe_test_lib_arg2 event",
		Trigger:      policytest.NewCmdTrigger(myBin).ExpectExitCode(0),
		EventChecker: ec.NewUnorderedEventChecker(upChecker),
	}
}).AddScenario(func(c *policytest.Conf) *policytest.Scenario {
	myBin := c.TestBinary("uprobe-test-1")
	upChecker := ec.NewProcessUprobeChecker("cel-multi-uprobe").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(myBin))).WithSymbol(sm.Full("uprobe_test_lib_arg1"))

	return &policytest.Scenario{
		Name:                 "check uprobe_test_lib_arg1 event does not occur",
		Trigger:              policytest.NewCmdTrigger(myBin).ExpectExitCode(0),
		EventChecker:         ec.NewUnorderedEventChecker(upChecker),
		ExpectCheckerFailure: true,
	}
}).RegisterAtInit()

var _ = policytest.NewBuilder("cel-multi-uprobe-both-match").WithLabels("uprobes").WithPolicyTemplate(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "cel-multi-uprobe"
spec:
  uprobes:
  - path: {{ testBinary "libuprobe.so" }}
    symbols:
    - "uprobe_test_lib_arg1"
    selectors:
    - matchArgs:
      - operator: CelExpr
        values:
        - "true"
  - path: {{ testBinary "libuprobe.so" }}
    symbols:
    - "uprobe_test_lib_arg2"
    selectors:
    - matchArgs:
      - operator: CelExpr
        values:
        - "true"
`).WithSkip(func(si *policytest.SkipInfo) string {
	if !si.AgentInfo.Probes[bpf.LargeProgsProbe] {
		return "need 5.3 or newer kernel"
	}

	if !si.AgentInfo.Probes[bpf.UprobeRefCtrOffsetProbe] {
		return "need uprobe ref_ctr_off support"
	}

	if !si.AgentInfo.Probes[bpf.MixBPFAndTailCallsProbe] {
		return "need kernel where we can mix bpf and tail calls"
	}

	return ""
}).AddScenario(func(c *policytest.Conf) *policytest.Scenario {
	myBin := c.TestBinary("uprobe-test-1")
	upArg2Checker := ec.NewProcessUprobeChecker("cel-multi-uprobe").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(myBin))).WithSymbol(sm.Full("uprobe_test_lib_arg2"))

	upArg1Checker := ec.NewProcessUprobeChecker("cel-multi-uprobe").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(myBin))).WithSymbol(sm.Full("uprobe_test_lib_arg1"))

	return &policytest.Scenario{
		Name:         "check both events occur",
		Trigger:      policytest.NewCmdTrigger(myBin).ExpectExitCode(0),
		EventChecker: ec.NewUnorderedEventChecker(upArg2Checker, upArg1Checker),
	}
}).RegisterAtInit()

var _ = policytest.NewBuilder("uprobe-postfix-shared-map").WithLabels("uprobes").WithPolicyTemplate(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe-postfix-shared-map"
spec:
  uprobes:
  - path: {{ testBinary "libuprobe.so" }}
    symbols:
    - "uprobe_test_lib_string_arg0"
    args:
    - index: 0
      type: "string"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Postfix"
        values:
        - "one"
  - path: {{ testBinary "libuprobe.so" }}
    symbols:
    - "uprobe_test_lib_string_arg1"
    args:
    - index: 1
      type: "string"
    selectors:
    - matchArgs:
      - index: 1
        operator: "Postfix"
        values:
        - "two"
`).WithSkip(func(si *policytest.SkipInfo) string {
	if !si.AgentInfo.Probes[bpf.UprobeMultiProbe] {
		return "need uprobe multi support"
	}
	if !si.AgentInfo.Probes[bpf.LargeProgsProbe] {
		return "need 5.3 or newer kernel"
	}
	if !si.AgentInfo.Probes[bpf.UprobeRefCtrOffsetProbe] {
		return "need uprobe ref_ctr_off support"
	}
	if !si.AgentInfo.Probes[bpf.MixBPFAndTailCallsProbe] {
		return "need kernel where we can mix bpf and tail calls"
	}
	if !si.AgentInfo.Probes[bpf.CopyFromUserStr] {
		return "Postfix operator requires bpf_copy_from_user_str kfunc"
	}
	return ""
}).AddScenario(func(c *policytest.Conf) *policytest.Scenario {
	bin := c.TestBinary("uprobe-test-1")
	arg0Checker := ec.NewProcessUprobeChecker("uprobe-postfix-shared-map").
		WithProcess(ec.NewProcessChecker().WithBinary(sm.Full(bin))).
		WithSymbol(sm.Full("uprobe_test_lib_string_arg0"))
	arg1Checker := ec.NewProcessUprobeChecker("uprobe-postfix-shared-map").
		WithProcess(ec.NewProcessChecker().WithBinary(sm.Full(bin))).
		WithSymbol(sm.Full("uprobe_test_lib_string_arg1"))

	return &policytest.Scenario{
		Name:         "check postfix maps remain distinct across attach points",
		Trigger:      policytest.NewCmdTrigger(bin).ExpectExitCode(0),
		EventChecker: ec.NewUnorderedEventChecker(arg0Checker, arg1Checker),
	}
}).RegisterAtInit()

var _ = policytest.NewBuilder("resolve-nested-anon-struct").WithLabels("uprobes").WithPolicyTemplate(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe"
spec:
  uprobes:
  - path: {{ testBinary "resolve-nested-anon-struct" }}
    btfPath: {{ testBinary "resolve-nested-anon-struct.btf" }}
    symbols:
    - "passit"
    args:
    - index: 0
      type: "int"
      resolve: "nested.ans.second"
      btfType: "mystruct"
    - index: 0
      type: "int"
      resolve: "pnested.pans.second"
      btfType: "mystruct"
`).WithSkip(func(si *policytest.SkipInfo) string {
	if !si.AgentInfo.Probes[bpf.LargeProgsProbe] {
		return "need 5.3 or newer kernel"
	}
	return ""
}).AddScenario(func(c *policytest.Conf) *policytest.Scenario {
	myBin := c.TestBinary("resolve-nested-anon-struct")
	checker := ec.NewProcessUprobeChecker("test-nested-anon-structs").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(myBin))).WithSymbol(sm.Full("passit")).WithArgs(ec.NewKprobeArgumentListMatcher().WithOperator(lc.Ordered).
		WithValues(
			ec.NewKprobeArgumentChecker().WithIntArg(7),
			ec.NewKprobeArgumentChecker().WithIntArg(77),
		))

	return &policytest.Scenario{
		Name:         "check both both args resolved correctly from nested anonymous structs",
		Trigger:      policytest.NewCmdTrigger(myBin).ExpectExitCode(0),
		EventChecker: ec.NewUnorderedEventChecker(checker),
	}
}).RegisterAtInit()

var _ = policytest.NewBuilder("uprobe-multiple-targets").WithLabels("uprobes").WithPolicyTemplate(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe-multiple-targets"
spec:
  uprobes:
  - path: {{ testBinary "uprobe-resolve" }}
    symbols:
    - "func"
  - path: {{ testBinary "nop" }}
    symbols:
    - "main"
`).AddScenario(func(c *policytest.Conf) *policytest.Scenario {
	binOne := c.TestBinary("uprobe-resolve")
	binTwo := c.TestBinary("nop")
	up1Checker := ec.NewProcessUprobeChecker(binOne).
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(binOne))).WithSymbol(sm.Full("func"))

	up2Checker := ec.NewProcessUprobeChecker(binTwo).
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(binTwo))).WithSymbol(sm.Full("main"))

	return &policytest.Scenario{
		Name: "check both events occur",
		Trigger: policytest.NewMultiCmdTrigger([]policytest.CmdTrigger{
			{
				Bin:  binOne,
				Args: []string{"v8", "7"},
			}, {
				Bin: binTwo,
			},
		}),
		EventChecker: ec.NewUnorderedEventChecker(up1Checker, up2Checker),
	}
}).RegisterAtInit()

var _ = policytest.NewBuilder("uprobe-override-new-symbol").WithLabels("uprobes").WithPolicyTemplate(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe-selector"
spec:
  uprobes:
  - path: {{ testBinary "libuprobe.so" }}
    symbols:
    - "uprobe_test_lib_string_arg_empty"
    args:
    - index: 0
      type: "int"
    selectors:
    - matchBinaries:
      - operator: "In"
        values:
        - {{ testBinary "uprobe-test-1" }}
      matchActions:
      - action: Override
        argNewSymbol: "uprobe_test_lib_string_arg__"
`).WithSkip(func(si *policytest.SkipInfo) string {
	if !si.AgentInfo.Probes[bpf.UprobeRegsChangeProbe] {
		return "need writing to regs kernel support (6.18+)"
	}
	return ""
}).AddScenario(func(c *policytest.Conf) *policytest.Scenario {
	bin := c.TestBinary("uprobe-test-1")
	upChecker := ec.NewProcessUprobeChecker("UPROBE_SELECTOR_MATCH").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(bin))).
		WithSymbol(sm.Full("uprobe_test_lib_string_arg_empty"))

	return &policytest.Scenario{
		Name: "check call was overridden",
		// See uprobe-lib.c/uprobe-test.c return code for uprobe_test_lib_string_arg__().
		// It will return 100 when the symbol is overridden.
		// It will be considered an error by `cmd.Run()`.
		Trigger:      policytest.NewCmdTrigger(bin).ExpectExitCode(100),
		EventChecker: ec.NewUnorderedEventChecker(upChecker),
	}
}).RegisterAtInit()

var _ = policytest.NewBuilder("uprobe-override-multiple-selectors").WithLabels("uprobes").WithPolicyTemplate(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe-multiple-selectors"
spec:
  uprobes:
  - path: {{ testBinary "libuprobe.so" }}
    symbols:
    - "uprobe_test_lib_string_arg_empty"
    args:
    - index: 0
      type: "string"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Equal"
        values:
          - ""
      matchActions:
      - action: Override
        argNewSymbol: "uprobe_test_lib_string_arg__"
  - path: {{ testBinary "libuprobe.so" }}
    symbols:
    - "uprobe_test_lib_string_arg1"
    args:
    - index: 0
      type: "int"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Equal"
        values:
          - "22"
      matchActions:
      - action: Override
        argError: 22
    - matchArgs:
      - index: 0
        operator: "Equal"
        values:
          - "33"
      matchActions:
      - action: Override
        argError: 33
`).WithSkip(func(si *policytest.SkipInfo) string {
	if !si.AgentInfo.Probes[bpf.UprobeRegsChangeProbe] {
		return "need writing to regs kernel support (6.18+)"
	}
	return ""
}).AddScenario(func(c *policytest.Conf) *policytest.Scenario {
	bin := c.TestBinary("uprobe-test-1")
	upChecker := ec.NewProcessUprobeChecker("UPROBE_SELECTOR_MATCH").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(bin))).
		WithSymbol(sm.Full("uprobe_test_lib_string_arg_empty"))
	upChecker1 := ec.NewProcessUprobeChecker("UPROBE_SELECTOR_MATCH").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(bin))).
		WithSymbol(sm.Full("uprobe_test_lib_string_arg1")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(ec.NewKprobeArgumentChecker().WithIntArg(22)))
	upChecker2 := ec.NewProcessUprobeChecker("UPROBE_SELECTOR_MATCH").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(bin))).
		WithSymbol(sm.Full("uprobe_test_lib_string_arg1")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(ec.NewKprobeArgumentChecker().WithIntArg(33)))

	return &policytest.Scenario{
		Name: "check all selectors work fine",
		// See uprobe-lib.c/uprobe-test.c return code for uprobe_test_lib_string_arg__().
		// It will return 100 when the symbol is overridden.
		// It will be considered an error by `cmd.Run()`.
		Trigger: policytest.NewMultiCmdTrigger([]policytest.CmdTrigger{
			{
				Bin: bin,
			}, {
				Bin:  bin,
				Args: []string{"22"},
			}, {
				Bin:  bin,
				Args: []string{"33"},
			},
		}).ExpectExitCodes([]int{100, 22, 33}),
		EventChecker: ec.NewUnorderedEventChecker(upChecker, upChecker1, upChecker2),
	}
}).RegisterAtInit()

var _ = policytest.NewBuilder("uprobe-multiple-string-preload").WithLabels("uprobes").WithPolicyTemplate(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe"
spec:
  uprobes:
  - path: {{ testBinary "uprobe-resolve" }}
    btfPath: {{ testBinary "uprobe-resolve.btf" }}
    symbols:
    - "func"
    args:
    - index: 1
      type: "string"
      btfType: "mystruct"
      resolve: "subp.buff"
    - index: 2
      type: "string"
      btfType: "mystruct"
      resolve: "subp.buff"
`).WithSkip(func(si *policytest.SkipInfo) string {
	if !si.AgentInfo.Probes[bpf.LargeProgsProbe] {
		return "need 5.3 or newer kernel"
	}

	if !si.AgentInfo.Probes[bpf.UprobeRefCtrOffsetProbe] {
		return "need uprobe ref_ctr_off support"
	}

	if !si.AgentInfo.Probes[bpf.CopyFromUserStr] {
		return "SubString operator requires bpf_copy_from_user_str kfunc"
	}

	return ""
}).AddScenario(func(c *policytest.Conf) *policytest.Scenario {
	bin := c.TestBinary("uprobe-resolve")
	upChecker := ec.NewProcessUprobeChecker("uprobe-resolve").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(bin)).
			WithArguments(
				sm.Full("subp.buff hello world!"),
			),
		).WithArgs(ec.NewKprobeArgumentListMatcher().
		WithOperator(lc.Ordered).
		WithValues(ec.NewKprobeArgumentChecker().WithStringArg(sm.Full("hello")),
			ec.NewKprobeArgumentChecker().WithStringArg(sm.Full("world!")),
		))

	return &policytest.Scenario{
		Name:         "check we can preload multiple strings",
		Trigger:      policytest.NewCmdTrigger(bin, "subp.buff", "hello", "world!"),
		EventChecker: ec.NewUnorderedEventChecker(upChecker),
	}
}).RegisterAtInit()

var _ = policytest.NewBuilder("uprobe-set").WithLabels("uprobes").WithPolicyTemplate(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe-set"
spec:
  uprobes:
  - path: {{ testBinary "uprobe-simple" }}
    symbols:
    - "manyargs"
    selectors:
    - matchActions:
      - action: Set
        argIndex: ` + strconv.Itoa(uprobeSetArgIndex()) + `
        argValue: ` + strconv.FormatUint(math.MaxUint32+1, 10) + `
`).WithSkip(func(si *policytest.SkipInfo) string {
	// skip if uprobe_regs_change is not supported
	if !si.AgentInfo.Probes[bpf.UprobeRegsChangeProbe] {
		return "uprobes cannot change registers"
	}
	return ""
}).AddScenario(func(c *policytest.Conf) *policytest.Scenario {
	myBin := c.TestBinary("uprobe-simple")
	upChecker := ec.NewProcessUprobeChecker("uprobe-set").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(myBin))).
		WithSymbol(sm.Full("manyargs"))

	argIndex := uprobeSetArgIndex()
	argVal := math.MaxUint32 + 1
	exitCode := 0 // math.MaxUint32+1 wraps to 0 since main() returns int
	if c.TestConf != nil && c.TestConf.MonitorMode {
		exitCode = argIndex
	}
	postCnt := uint64(1)
	setCnt := uint64(1)

	trigger := policytest.NewCmdTrigger(myBin, strconv.Itoa(argIndex)).ExpectExitCode(exitCode)
	if uprobeSetArgIndex() == 5 {
		trigger.ExpectedStdout = []string{fmt.Sprintf("manyargs was passed: %d,%d,%d,%d,%d,%d,%d,%d and retargidx: %d", 0, 1, 2, 3, 4, argVal, 6, 7, uprobeSetArgIndex())}
	} else {
		trigger.ExpectedStdout = []string{fmt.Sprintf("manyargs was passed: %d,%d,%d,%d,%d,%d,%d,%d and retargidx: %d", 0, 1, 2, 3, 4, 5, 6, argVal, uprobeSetArgIndex())}
	}
	return &policytest.Scenario{
		Name:         "execute uprobe-simple, check set action and events",
		Trigger:      trigger,
		EventChecker: ec.NewUnorderedEventChecker(upChecker),
		ActCountChecker: policytest.ActionCounts{
			Post: &postCnt,
			Set:  &setCnt,
		},
	}
}).RegisterAtInit()

var _ = policytest.NewBuilder("uprobe-override-set").WithLabels("uprobes").WithPolicyTemplate(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe-override-set"
spec:
  uprobes:
  - path: {{ testBinary "uprobe-simple" }}
    symbols:
    - "pizza"
    selectors:
    - matchActions:
      - action: Override
        argNewSymbol: "lasagna"
      - action: Set
        argIndex: 0
        argValue: 42
`).WithSkip(func(si *policytest.SkipInfo) string {
	// skip if uprobe_regs_change is not supported
	if !si.AgentInfo.Probes[bpf.UprobeRegsChangeProbe] {
		return "uprobes cannot change registers"
	}
	return ""
}).AddScenario(func(c *policytest.Conf) *policytest.Scenario {
	myBin := c.TestBinary("uprobe-simple")
	upChecker := ec.NewProcessUprobeChecker("uprobe-override-set").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(myBin))).
		WithSymbol(sm.Full("pizza"))

	// see uprobe-simple.c: lasagna() returns (param - 10)
	exitCode := 32
	if c.TestConf != nil && c.TestConf.MonitorMode {
		exitCode = 0
	}
	postCnt := uint64(1)
	setCnt := uint64(1)
	overrideCnt := uint64(1)
	return &policytest.Scenario{
		Name:         "execute uprobe-simple, check set action and events",
		Trigger:      policytest.NewCmdTrigger(myBin).ExpectExitCode(exitCode),
		EventChecker: ec.NewUnorderedEventChecker(upChecker),
		ActCountChecker: policytest.ActionCounts{
			Post:     &postCnt,
			Set:      &setCnt,
			Override: &overrideCnt,
		},
	}
}).RegisterAtInit()

var _ = policytest.NewBuilder("uprobe-caller").WithLabels("uprobes").WithPolicyTemplate(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe-caller"
spec:
  uprobes:
  - path: {{ testBinary "uprobe-caller" }}
    symbols:
    - "func2"
    selectors:
    - matchUserCallers:
      - depth: "2"
        symbol: "main"
    - matchActions:
      - action: NoPost
    message: "shouldTrigger"
  - path: {{ testBinary "uprobe-caller" }}
    symbols:
    - "func2"
    selectors:
    - matchUserCallers:
      - depth: "2"
        symbol: "func1"
    - matchActions:
      - action: NoPost
    message: "shouldNotTrigger"
`).WithSkip(func(si *policytest.SkipInfo) string {
	if !si.AgentInfo.Probes[bpf.LargeProgsProbe] || !si.AgentInfo.Probes[bpf.SignalHelperProbe] {
		return "need 5.3 or newer kernel"
	}
	return ""
}).AddScenario(func(c *policytest.Conf) *policytest.Scenario {
	uprobeCaller := c.TestBinary("uprobe-caller")
	upChecker := ec.NewProcessUprobeChecker("uprobe-caller").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(uprobeCaller))).
		WithSymbol(sm.Full("func2"))

	postCnt := uint64(1)
	return &policytest.Scenario{
		Name:         "execute uprobe-caller, check matchUserCallers",
		Trigger:      policytest.NewCmdTrigger(uprobeCaller).ExpectExitCode(3),
		EventChecker: ec.NewUnorderedEventChecker(upChecker),
		ActCountChecker: policytest.ActionCounts{
			Post: &postCnt,
		},
	}
}).RegisterAtInit()

var _ = policytest.NewBuilder("uprobe-caller-mixed").WithLabels("uprobes").
	WithTemplateFunc("resolveFuncStart", resolveFuncStart).
	WithTemplateFunc("resolveFuncEnd", resolveFuncEnd).
	WithPolicyTemplate(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe-caller-mixed"
spec:
  uprobes:
  - path: {{ testBinary "uprobe-caller" }}
    symbols:
    - "func2"
    selectors:
    - matchUserCallers:
      - depth: "any"
        symbol: "func3" # is not a caller of func2
      matchActions:
      - action: Override
        argError: 123
    - matchActions:
      - action: NoPost
    message: "shouldNotTrigger1"
  - path: {{ testBinary "uprobe-caller" }}
    symbols:
    - "func3"
    selectors:
    - matchUserCallers:
      - depth: "5" # wrong depth
        symbol: "func2"
      - depth: "any"
        symbol: "main"
      matchActions:
      - action: Override
        argError: 123
    - matchActions:
      - action: NoPost
    message: "shouldNotTrigger2"
  - path: {{ testBinary "uprobe-caller" }}
    symbols:
    - "func3"
    args:
    - index: 0
      type: "int"
    selectors:
    - matchUserCallers:
      - depth: "1"
        symbol: "func2"
      - depth: "2"
        symbol: "func1"
      matchArgs:
      - index: 0
        operator: "Equal"
        values:
        - "-1" # wrong arg value
    message: "shouldNotTrigger3"
  - path: {{ testBinary "uprobe-caller" }}
    symbols:
    - "func3"
    args:
    - index: 0
      type: "int"
    selectors:
    - matchUserCallers:
      - depth: "1"
        symbol: "func2"
      - depth: "2"
        startRange: {{ (resolveFuncStart (testBinary "uprobe-caller") "func1") }}
        endRange: {{ (resolveFuncEnd (testBinary "uprobe-caller") "func1") }}
      matchArgs:
      - index: 0
        operator: "Equal"
        values:
        - "1"
      matchActions:
      - action: Override
        argError: 42
    - matchActions:
      - action: NoPost
    message: "shouldTrigger"
`).WithSkip(func(si *policytest.SkipInfo) string {
	// skip if uprobe_regs_change is not supported
	if !si.AgentInfo.Probes[bpf.UprobeRegsChangeProbe] {
		return "uprobes cannot change registers"
	}
	if runtime.GOARCH == "arm64" {
		return "immediate caller not available on arm64"
	}
	return ""
}).AddScenario(func(c *policytest.Conf) *policytest.Scenario {
	uprobeCaller := c.TestBinary("uprobe-caller")
	upChecker := ec.NewProcessUprobeChecker("uprobe-caller").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(uprobeCaller))).
		WithSymbol(sm.Full("func3")).
		WithMessage(sm.Contains("shouldTrigger"))

	exitCode := 44
	if c.TestConf != nil && c.TestConf.MonitorMode {
		exitCode = 3
	}
	postCnt := uint64(1)
	overrideCount := uint64(1)
	return &policytest.Scenario{
		Name:         "execute uprobe-caller, check matchCallers",
		Trigger:      policytest.NewCmdTrigger(uprobeCaller).ExpectExitCode(exitCode),
		EventChecker: ec.NewUnorderedEventChecker(upChecker),
		ActCountChecker: policytest.ActionCounts{
			Post:     &postCnt,
			Override: &overrideCount,
		},
	}
}).RegisterAtInit()

var _ = policytest.NewBuilder("uprobe-multi-override-new-symbol-so").WithLabels("uprobes").WithPolicyTemplate(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe-mulit-override-new-symbol-so"
spec:
  uprobes:
  - path: {{ testBinary "uprobe-simple" }}
    symbols:
    - "pizza"
    - "lasagna"
    - "maccheroni"
    selectors:
    - matchActions:
      - action: Override
        argNewSymbol: uprobe_test_lib_pizza
        sopath: {{ testBinary "libuprobe.so" }}
`).WithSkip(func(si *policytest.SkipInfo) string {
	if !si.AgentInfo.Probes[bpf.UprobeMultiProbe] {
		return "need uprobe multi support"
	}

	if !si.AgentInfo.Probes[bpf.UprobeRegsChangeProbe] {
		return "uprobes cannot change registers"
	}

	if !si.AgentInfo.Probes[bpf.CopyFromUserStr] {
		return "SubString operator requires bpf_copy_from_user_str kfunc"
	}

	return ""
}).AddScenario(func(c *policytest.Conf) *policytest.Scenario {
	bin := c.TestBinary("uprobe-simple")
	upChecker := ec.NewProcessUprobeChecker("uprobe-simple").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(bin)))

	// Multi uprobe; symbols share the attached program.
	//
	// we trigger uprobed symbols 7 times: 3 times for real:
	// * 1 time pizza()
	// * 1 time lasagna (cached call)
	// * 1 time normally from a secondary thread (maccheroni())
	// plus 2 times while resolving the symbol from sopath on each thread,
	// since the sopath override implementation re-triggers the symbol itself
	// instead of attaching uretprobes to mmap and dlopen.
	overrideCount := uint64(3) + 4
	return &policytest.Scenario{
		Name:         "check calls were overridden with symbol loaded by SO",
		Trigger:      policytest.NewCmdTrigger(bin).ExpectExitCode(33), // 1 + 11 + 21
		EventChecker: ec.NewUnorderedEventChecker(upChecker),
		ActCountChecker: policytest.ActionCounts{
			Override: &overrideCount,
		},
	}
}).RegisterAtInit()

// Two uprobes entries in the same policy redirect two different symbols to two
// different replacements loaded from sopath. With uprobe multi, both entries
// share the attached program, so the per-thread resolution state must keep
// the two targets apart. See uprobe-two-targets.c for the exit code.
var _ = policytest.NewBuilder("uprobe-multi-override-new-symbol-so-two-targets").WithLabels("uprobes").WithPolicyTemplate(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe-multi-override-new-symbol-so-two-targets"
spec:
  uprobes:
  - path: {{ testBinary "uprobe-two-targets" }}
    symbols:
    - "first_target"
    selectors:
    - matchActions:
      - action: Override
        argNewSymbol: uprobe_test_lib_first_target
        sopath: {{ testBinary "libuprobe.so" }}
  - path: {{ testBinary "uprobe-two-targets" }}
    symbols:
    - "second_target"
    selectors:
    - matchActions:
      - action: Override
        argNewSymbol: uprobe_test_lib_second_target
        sopath: {{ testBinary "libuprobe.so" }}
`).WithSkip(func(si *policytest.SkipInfo) string {
	if !si.AgentInfo.Probes[bpf.UprobeMultiProbe] {
		return "need uprobe multi support"
	}
	if !si.AgentInfo.Probes[bpf.UprobeRegsChangeProbe] {
		return "uprobes cannot change registers"
	}
	return ""
}).AddScenario(func(c *policytest.Conf) *policytest.Scenario {
	bin := c.TestBinary("uprobe-two-targets")
	firstChecker := ec.NewProcessUprobeChecker("uprobe-two-targets-first").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(bin))).
		WithSymbol(sm.Full("first_target"))
	secondChecker := ec.NewProcessUprobeChecker("uprobe-two-targets-second").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(bin))).
		WithSymbol(sm.Full("second_target"))

	return &policytest.Scenario{
		Name:         "check each symbol is redirected to its own replacement loaded by SO",
		Trigger:      policytest.NewCmdTrigger(bin).ExpectExitCode(0),
		EventChecker: ec.NewUnorderedEventChecker(firstChecker, secondChecker),
	}
}).RegisterAtInit()

// One uprobes entry with two selectors, each redirecting the same symbol to a
// different replacement loaded from sopath, depending on the calling binary.
// Each trigger runs a separate process doing a single call, so only the
// per-selector override configuration is tested. See uprobe-selector-targets.c.
var _ = policytest.NewBuilder("uprobe-override-new-symbol-so-selector-targets").WithLabels("uprobes").WithPolicyTemplate(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe-override-new-symbol-so-selector-targets"
spec:
  uprobes:
  - path: {{ testBinary "libuprobe.so" }}
    symbols:
    - "uprobe_test_lib_selector_target"
    selectors:
    - matchBinaries:
      - operator: "In"
        values:
        - {{ testBinary "uprobe-selector-targets-1" }}
      matchActions:
      - action: Override
        argNewSymbol: uprobe_test_lib_first_target
        sopath: {{ testBinary "libuprobe.so" }}
    - matchBinaries:
      - operator: "In"
        values:
        - {{ testBinary "uprobe-selector-targets-2" }}
      matchActions:
      - action: Override
        argNewSymbol: uprobe_test_lib_second_target
        sopath: {{ testBinary "libuprobe.so" }}
`).WithSkip(func(si *policytest.SkipInfo) string {
	if !si.AgentInfo.Probes[bpf.UprobeRegsChangeProbe] {
		return "uprobes cannot change registers"
	}
	return ""
}).AddScenario(func(c *policytest.Conf) *policytest.Scenario {
	bin1 := c.TestBinary("uprobe-selector-targets-1")
	bin2 := c.TestBinary("uprobe-selector-targets-2")
	binChecker := func(bin string) *ec.ProcessUprobeChecker {
		return ec.NewProcessUprobeChecker("uprobe-selector-targets").
			WithProcess(ec.NewProcessChecker().
				WithBinary(sm.Full(bin))).
			WithSymbol(sm.Full("uprobe_test_lib_selector_target"))
	}

	return &policytest.Scenario{
		Name: "check each selector redirects to its own replacement loaded by SO",
		// The exit code is the value returned by the replacement.
		Trigger: policytest.NewMultiCmdTrigger([]policytest.CmdTrigger{
			{Bin: bin1},
			{Bin: bin2},
		}).ExpectExitCodes([]int{1, 2}),
		EventChecker: ec.NewUnorderedEventChecker(binChecker(bin1), binChecker(bin2)),
	}
}).RegisterAtInit()

// Same as uprobe-override-new-symbol-so-selector-targets, but redirecting to
// replacements in the traced binary, without sopath.
var _ = policytest.NewBuilder("uprobe-override-new-symbol-selector-targets").WithLabels("uprobes").WithPolicyTemplate(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe-override-new-symbol-selector-targets"
spec:
  uprobes:
  - path: {{ testBinary "libuprobe.so" }}
    symbols:
    - "uprobe_test_lib_selector_target"
    selectors:
    - matchBinaries:
      - operator: "In"
        values:
        - {{ testBinary "uprobe-selector-targets-1" }}
      matchActions:
      - action: Override
        argNewSymbol: uprobe_test_lib_first_target
    - matchBinaries:
      - operator: "In"
        values:
        - {{ testBinary "uprobe-selector-targets-2" }}
      matchActions:
      - action: Override
        argNewSymbol: uprobe_test_lib_second_target
`).WithSkip(func(si *policytest.SkipInfo) string {
	if !si.AgentInfo.Probes[bpf.UprobeRegsChangeProbe] {
		return "uprobes cannot change registers"
	}
	return ""
}).AddScenario(func(c *policytest.Conf) *policytest.Scenario {
	bin1 := c.TestBinary("uprobe-selector-targets-1")
	bin2 := c.TestBinary("uprobe-selector-targets-2")
	binChecker := func(bin string) *ec.ProcessUprobeChecker {
		return ec.NewProcessUprobeChecker("uprobe-selector-targets").
			WithProcess(ec.NewProcessChecker().
				WithBinary(sm.Full(bin))).
			WithSymbol(sm.Full("uprobe_test_lib_selector_target"))
	}

	return &policytest.Scenario{
		Name: "check each selector redirects to its own replacement",
		// The exit code is the value returned by the replacement.
		Trigger: policytest.NewMultiCmdTrigger([]policytest.CmdTrigger{
			{Bin: bin1},
			{Bin: bin2},
		}).ExpectExitCodes([]int{1, 2}),
		EventChecker: ec.NewUnorderedEventChecker(binChecker(bin1), binChecker(bin2)),
	}
}).RegisterAtInit()

var _ = policytest.NewBuilder("uprobe-override-new-symbol-so").WithLabels("uprobes").WithPolicyTemplate(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe-override-new-symbol-so"
spec:
  options:
  - name: "disable-uprobe-multi"
    value: "1"
  uprobes:
  - path: {{ testBinary "uprobe-simple" }}
    symbols:
    - "pizza"
    - "lasagna"
    - "maccheroni"
    selectors:
    - matchActions:
      - action: Override
        argNewSymbol: uprobe_test_lib_pizza
        sopath: {{ testBinary "libuprobe.so" }}
`).WithSkip(func(si *policytest.SkipInfo) string {
	if !si.AgentInfo.Probes[bpf.UprobeRegsChangeProbe] {
		return "uprobes cannot change registers"
	}

	if !si.AgentInfo.Probes[bpf.CopyFromUserStr] {
		return "SubString operator requires bpf_copy_from_user_str kfunc"
	}

	return ""
}).AddScenario(func(c *policytest.Conf) *policytest.Scenario {
	bin := c.TestBinary("uprobe-simple")
	upChecker := ec.NewProcessUprobeChecker("uprobe-simple").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(bin)))

	// Single uprobe; each symbol has its own attached program.
	//
	// We trigger uprobed symbols 9 times.
	// 3 times for real:
	// * 1 time pizza()
	// * 1 time lasagna()
	// * 1 time normally from a secondary thread (maccheroni())
	// plus 2 times while resolving the symbol from sopath on each invocation,
	// since the sopath override implementation re-triggers the symbol itself
	// instead of attaching uretprobes to mmap and dlopen.
	// thus ending up with 3 uprobe triggers for each symbol.
	// NOTE: lasagna() call is non-cached in non-multi-uprobe mode
	// because tg_dyn_sm is program specific, and each symbol has its own program.
	overrideCount := uint64(3) * 3
	return &policytest.Scenario{
		Name:         "check calls were overridden with symbol loaded by SO",
		Trigger:      policytest.NewCmdTrigger(bin).ExpectExitCode(33), // 1 + 11 + 21
		EventChecker: ec.NewUnorderedEventChecker(upChecker),
		ActCountChecker: policytest.ActionCounts{
			Override: &overrideCount,
		},
	}
}).RegisterAtInit()

// Floating-point arguments are passed in xmm0-xmm7 (x86_64) or v0-v7 (arm64),
// which cannot be saved by BPF across the mmap()/dlopen() detour done while
// resolving the symbol from sopath. See uprobe-fp-args.c for the exit code.
var _ = policytest.NewBuilder("uprobe-override-new-symbol-so-fp-args").WithLabels("uprobes").WithPolicyTemplate(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe-override-new-symbol-so-fp-args"
spec:
  uprobes:
  - path: {{ testBinary "uprobe-fp-args" }}
    symbols:
    - "fp_args"
    selectors:
    - matchActions:
      - action: Override
        argNewSymbol: uprobe_test_lib_fp_args
        sopath: {{ testBinary "libuprobe.so" }}
`).WithSkip(func(si *policytest.SkipInfo) string {
	if !si.AgentInfo.Probes[bpf.UprobeRegsChangeProbe] {
		return "uprobes cannot change registers"
	}
	return ""
}).AddScenario(func(c *policytest.Conf) *policytest.Scenario {
	bin := c.TestBinary("uprobe-fp-args")
	upChecker := ec.NewProcessUprobeChecker("uprobe-fp-args").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(bin))).
		WithSymbol(sm.Full("fp_args"))

	return &policytest.Scenario{
		Name:         "check floating-point arguments are preserved while resolving symbol from SO",
		Trigger:      policytest.NewCmdTrigger(bin).ExpectExitCode(0),
		EventChecker: ec.NewUnorderedEventChecker(upChecker),
	}
}).RegisterAtInit()

// GCC nested functions receive a pointer to the enclosing function's frame in
// the static chain register (r10 on x86_64, x18 on arm64), a hidden argument
// that must be preserved across the mmap()/dlopen() detour done while
// resolving the symbol from sopath. See uprobe-static-chain.c for the exit
// code and how the replacement library is built.
var _ = policytest.NewBuilder("uprobe-override-new-symbol-so-static-chain").WithLabels("uprobes").WithPolicyTemplate(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe-override-new-symbol-so-static-chain"
spec:
  uprobes:
  - path: {{ testBinary "uprobe-static-chain" }}
    symbols:
    - "static_chain_target.0"
    selectors:
    - matchActions:
      - action: Override
        argNewSymbol: "static_chain_target.0"
        sopath: {{ testBinary "libuprobe-static-chain.so" }}
`).WithSkip(func(si *policytest.SkipInfo) string {
	if !si.AgentInfo.Probes[bpf.UprobeRegsChangeProbe] {
		return "uprobes cannot change registers"
	}
	return ""
}).AddScenario(func(c *policytest.Conf) *policytest.Scenario {
	bin := c.TestBinary("uprobe-static-chain")
	upChecker := ec.NewProcessUprobeChecker("uprobe-static-chain").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(bin))).
		WithSymbol(sm.Full("static_chain_target.0"))

	return &policytest.Scenario{
		Name:         "check static chain register is preserved while resolving symbol from SO",
		Trigger:      policytest.NewCmdTrigger(bin).ExpectExitCode(0),
		EventChecker: ec.NewUnorderedEventChecker(upChecker),
	}
}).RegisterAtInit()

// Structs larger than 16 bytes are returned through memory: the caller passes
// the result address in x8 on arm64 (in rdi on x86_64), which must be
// preserved across the mmap()/dlopen() detour done while resolving the symbol
// from sopath. See uprobe-big-struct.c for the exit code.
var _ = policytest.NewBuilder("uprobe-override-new-symbol-so-big-struct").WithLabels("uprobes").WithPolicyTemplate(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe-override-new-symbol-so-big-struct"
spec:
  uprobes:
  - path: {{ testBinary "uprobe-big-struct" }}
    symbols:
    - "big_struct_ret"
    selectors:
    - matchActions:
      - action: Override
        argNewSymbol: uprobe_test_lib_big_struct
        sopath: {{ testBinary "libuprobe.so" }}
`).WithSkip(func(si *policytest.SkipInfo) string {
	if !si.AgentInfo.Probes[bpf.UprobeRegsChangeProbe] {
		return "uprobes cannot change registers"
	}
	return ""
}).AddScenario(func(c *policytest.Conf) *policytest.Scenario {
	bin := c.TestBinary("uprobe-big-struct")
	upChecker := ec.NewProcessUprobeChecker("uprobe-big-struct").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(bin))).
		WithSymbol(sm.Full("big_struct_ret"))

	return &policytest.Scenario{
		Name:         "check struct return address is preserved while resolving symbol from SO",
		Trigger:      policytest.NewCmdTrigger(bin).ExpectExitCode(0),
		EventChecker: ec.NewUnorderedEventChecker(upChecker),
	}
}).RegisterAtInit()

// resolveFuncStart is a helper function to be used in the yaml.
func resolveFuncStart(bin, funcName string) (uint64, error) {
	se, err := telf.OpenSafeELFFile(bin)
	if err != nil {
		return 0, fmt.Errorf("failed to open '%s': %w", bin, err)
	}
	defer se.Close()

	addr, err := se.Offset(funcName)
	if err != nil {
		return 0, fmt.Errorf("failed to resolve '%s' in '%s': %w", funcName, bin, err)
	}

	return addr, nil
}

// resolveFuncEnd is a helper function to be used in the yaml.
func resolveFuncEnd(bin, funcName string) (uint64, error) {
	se, err := telf.OpenSafeELFFile(bin)
	if err != nil {
		return 0, fmt.Errorf("failed to open '%s': %w", bin, err)
	}
	defer se.Close()

	addr, err := se.Offset(funcName)
	if err != nil {
		return 0, fmt.Errorf("failed to resolve '%s' in '%s': %w", funcName, bin, err)
	}

	size, err := se.SymbolSize(funcName)
	if err != nil {
		return 0, fmt.Errorf("failed to resolve size of '%s' in '%s': %w", funcName, bin, err)
	}

	return addr + size - 1, nil
}
