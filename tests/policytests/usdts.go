// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tests

import (
	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/bpf"
	lc "github.com/cilium/tetragon/pkg/matchers/listmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/testutils/policytest"
)

var _ = policytest.NewBuilder("usdt-resolve-casts").WithLabels("usdt").WithPolicyTemplate(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "usdt-resolve-casts"
spec:
  usdts:
  - path: {{ testBinary "usdt-resolve" }}
    btfPath: {{ testBinary "usdt-resolve.btf" }}
    provider: "tetragon"
    name: "test"
    args:
    - index: 1
      type: "uint32"
      btfType: "mystruct"
      resolve: "sub.as(struct mysubstruct).v32"
    - index: 1
      type: "int32"
      btfType: "mystruct"
      resolve: "sub.v32.as(int32)"
    - index: 1
      type: "uint32"
      btfType: "mystruct"
      resolve: "sub.as(uint32[4])[3]"
    - index: 1
      type: "int32"
      btfType: "mystruct"
      resolve: "sub.as(uint32[4])[3].as(int32)"
`).WithSkip(func(si *policytest.SkipInfo) string {
	if !si.AgentInfo.Probes[bpf.LargeProgsProbe] {
		return "need 5.3 or newer kernel"
	}
	if !si.AgentInfo.Probes[bpf.UprobeRefCtrOffsetProbe] {
		return "need uprobe ref_ctr_off support"
	}
	return ""
}).AddScenario(func(c *policytest.Conf) *policytest.Scenario {
	bin := c.TestBinary("usdt-resolve")
	checker := ec.NewProcessUsdtChecker("usdt-resolve-casts").
		WithProcess(ec.NewProcessChecker().WithBinary(sm.Full(bin))).
		WithProvider(sm.Full("tetragon")).
		WithName(sm.Full("test")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithUintArg(1<<31),
				ec.NewKprobeArgumentChecker().WithIntArg(-1<<31),
				ec.NewKprobeArgumentChecker().WithUintArg(1<<31),
				ec.NewKprobeArgumentChecker().WithIntArg(-1<<31),
			))
	return &policytest.Scenario{
		Name:         "resolve struct, indexed and terminal casts",
		Trigger:      policytest.NewCmdTrigger(bin, "sub.v32", "2147483648").ExpectExitCode(0),
		EventChecker: ec.NewUnorderedEventChecker(checker),
	}
}).RegisterAtInit()

var _ = policytest.NewBuilder("usdt-set").WithLabels("usdt").WithPolicyTemplate(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "usdts"
spec:
  usdts:
  - path: {{ testBinary "usdt-override" }}
    provider: "tetragon"
    name: "test_4B"
    args:
    - index: 0
      type: "int32"
    - index: 1
      type: "int32"
    - index: 2
      type: "int32"
    selectors:
    - matchActions:
      - action: Set
        argIndex: 0
        argValue: 240
`).WithSkip(func(si *policytest.SkipInfo) string {
	if !si.AgentInfo.Probes[bpf.LargeProgsProbe] {
		return "need 5.3 or newer kernel"
	}
	if !si.AgentInfo.Probes[bpf.UprobeRefCtrOffsetProbe] {
		return "need uprobe ref_ctr_off support"
	}
	if !si.AgentInfo.Probes[bpf.ProbeWriteUserProbe] {
		return "need probe_write_user() helper"
	}
	return ""
}).AddScenario(func(c *policytest.Conf) *policytest.Scenario {
	myBin := c.TestBinary("usdt-override")
	upChecker := ec.NewProcessUsdtChecker("USDT").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(myBin))).
		WithProvider(sm.Full("tetragon")).
		WithName(sm.Full("test_4B")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(0),
				ec.NewKprobeArgumentChecker().WithIntArg(321),
				ec.NewKprobeArgumentChecker().WithIntArg(123),
			)).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_SET)
	exitCode := 240
	if c.TestConf != nil && c.TestConf.MonitorMode {
		exitCode = 0
	}
	postCnt := uint64(1)
	setCnt := uint64(1)
	return &policytest.Scenario{
		Name:         "execute usdt-override, check enforcement and events",
		Trigger:      policytest.NewCmdTrigger(myBin, "321", "123").ExpectExitCode(exitCode),
		EventChecker: ec.NewUnorderedEventChecker(upChecker),
		ActCountChecker: policytest.ActionCounts{
			Post: &postCnt,
			Set:  &setCnt,
		},
	}
}).RegisterAtInit()

var _ = policytest.NewBuilder("usdt-load-selector-maps").WithLabels("usdt").WithPolicyTemplate(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: usdt-argfilter-inmap-repro
spec:
  usdts:
    - path: {{ testBinary "usdt-override" }}
      provider: "tetragon"
      name: "test_4B"
      args:
        - index: 1
          type: "int32"
      selectors:
        - matchArgs:
            - index: 1
              operator: "InMap"
              values:
                - "321"
                - "7"

`).WithSkip(func(si *policytest.SkipInfo) string {
	if !si.AgentInfo.Probes[bpf.LargeProgsProbe] {
		return "need 5.3 or newer kernel"
	}
	if !si.AgentInfo.Probes[bpf.UprobeRefCtrOffsetProbe] {
		return "need uprobe ref_ctr_off support"
	}
	return ""
}).AddScenario(func(c *policytest.Conf) *policytest.Scenario {
	myBin := c.TestBinary("usdt-override")
	upChecker := ec.NewProcessUsdtChecker("USDT").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(myBin))).
		WithProvider(sm.Full("tetragon")).
		WithName(sm.Full("test_4B")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(321),
			))

	return &policytest.Scenario{
		Name:         "load selector maps",
		Trigger:      policytest.NewCmdTrigger(myBin, "321", "123").ExpectExitCode(0),
		EventChecker: ec.NewUnorderedEventChecker(upChecker),
	}
}).RegisterAtInit()
