// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tests

import (
	"runtime"
	"strings"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/bpf"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/testutils/policytest"
)

func celRegsExpand() *strings.Replacer {
	if runtime.GOARCH == "arm64" {
		return strings.NewReplacer("R0", "x0", "R1", "x1", "R2", "x2")
	}
	return strings.NewReplacer("R0", "rdi", "R1", "rsi", "R2", "rdx")
}

func celRegsChecker(bin, symbol string) *ec.UnorderedEventChecker {
	return ec.NewUnorderedEventChecker(
		ec.NewProcessUprobeChecker("cel-regs-override").
			WithProcess(ec.NewProcessChecker().
				WithBinary(sm.Full(bin))).
			WithSymbol(sm.Full(symbol)))
}

var _ = policytest.NewBuilder("cel-regs-override").
	WithLabels("uprobes", "cel").
	WithSkip(func(si *policytest.SkipInfo) string {
		if !si.AgentInfo.Probes[bpf.UprobeRegsChangeProbe] {
			return "need writing to regs kernel support (6.18+)"
		}
		if !si.AgentInfo.Probes[bpf.MixBPFAndTailCallsProbe] {
			return "need kernel where we can mix bpf and tail calls"
		}
		return ""
	}).
	WithPolicyTemplate(celRegsExpand().Replace(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "cel-regs-override"
spec:
  uprobes:
  - path: {{ testBinary "cel-regs-override" }}
    symbols:
    - "cel_const"
    selectors:
    - matchActions:
      - action: Override
        argRegs:
        - "R0=cel(41 + 1)"
  - path: {{ testBinary "cel-regs-override" }}
    symbols:
    - "cel_one_reg"
    data:
    - index: 0
      type: "int64"
      source: "pt_regs"
      resolve: "R0"
    selectors:
    - matchActions:
      - action: Override
        argRegs:
        - "R0=cel(data0 + 1)"
  - path: {{ testBinary "cel-regs-override" }}
    symbols:
    - "cel_multi_reg"
    data:
    - index: 0
      type: "int64"
      source: "pt_regs"
      resolve: "R0"
    - index: 1
      type: "int64"
      source: "pt_regs"
      resolve: "R1"
    - index: 2
      type: "int64"
      source: "pt_regs"
      resolve: "R2"
    selectors:
    - matchActions:
      - action: Override
        argRegs:
        - "R0=cel(data0 - data1 + data2)"
  - path: {{ testBinary "cel-regs-override" }}
    symbols:
    - "cel_bitwise"
    data:
    - index: 0
      type: "int64"
      source: "pt_regs"
      resolve: "R0"
    - index: 1
      type: "int64"
      source: "pt_regs"
      resolve: "R1"
    selectors:
    - matchActions:
      - action: Override
        argRegs:
        - "R0=cel(and(data0, data1))"
`)).
	AddScenario(func(c *policytest.Conf) *policytest.Scenario {
		bin := c.TestBinary("cel-regs-override")
		exitCode := 42
		if c.TestConf != nil && c.TestConf.MonitorMode {
			exitCode = 0
		}
		return &policytest.Scenario{
			Name:         "constant expression, no data items",
			Trigger:      policytest.NewCmdTrigger(bin, "const", "0", "0", "0").ExpectExitCode(exitCode),
			EventChecker: celRegsChecker(bin, "cel_const"),
		}
	}).
	AddScenario(func(c *policytest.Conf) *policytest.Scenario {
		bin := c.TestBinary("cel-regs-override")
		exitCode := 11
		if c.TestConf != nil && c.TestConf.MonitorMode {
			exitCode = 10
		}
		return &policytest.Scenario{
			Name:         "one pt_regs data item plus a literal",
			Trigger:      policytest.NewCmdTrigger(bin, "one_reg", "10", "0", "0").ExpectExitCode(exitCode),
			EventChecker: celRegsChecker(bin, "cel_one_reg"),
		}
	}).
	AddScenario(func(c *policytest.Conf) *policytest.Scenario {
		bin := c.TestBinary("cel-regs-override")
		exitCode := 12
		if c.TestConf != nil && c.TestConf.MonitorMode {
			exitCode = 10
		}
		return &policytest.Scenario{
			Name:         "three pt_regs data items",
			Trigger:      policytest.NewCmdTrigger(bin, "multi_reg", "10", "3", "5").ExpectExitCode(exitCode),
			EventChecker: celRegsChecker(bin, "cel_multi_reg"),
		}
	}).
	AddScenario(func(c *policytest.Conf) *policytest.Scenario {
		bin := c.TestBinary("cel-regs-override")
		exitCode := 8
		if c.TestConf != nil && c.TestConf.MonitorMode {
			exitCode = 12
		}
		return &policytest.Scenario{
			Name:         "bitwise and() of two pt_regs data items",
			Trigger:      policytest.NewCmdTrigger(bin, "bitwise", "12", "10", "0").ExpectExitCode(exitCode),
			EventChecker: celRegsChecker(bin, "cel_bitwise"),
		}
	}).
	RegisterAtInit()

var _ = policytest.NewBuilder("cel-regs-ordering").
	WithLabels("uprobes", "cel").
	WithSkip(func(si *policytest.SkipInfo) string {
		if !si.AgentInfo.Probes[bpf.UprobeRegsChangeProbe] {
			return "need writing to regs kernel support (6.18+)"
		}
		if !si.AgentInfo.Probes[bpf.MixBPFAndTailCallsProbe] {
			return "need kernel where we can mix bpf and tail calls"
		}
		return ""
	}).
	WithPolicyTemplate(celRegsExpand().Replace(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "cel-regs-ordering"
spec:
  uprobes:
  - path: {{ testBinary "cel-regs-override" }}
    symbols:
    - "cel_ordering"
    data:
    - index: 0
      type: "int64"
      source: "pt_regs"
      resolve: "R0"
    - index: 1
      type: "int64"
      source: "pt_regs"
      resolve: "R1"
    selectors:
    - matchActions:
      - action: Override
        argRegs:
        - "R1=100"
        - "R0=cel(data0 + data1)"
`)).
	AddScenario(func(c *policytest.Conf) *policytest.Scenario {
		bin := c.TestBinary("cel-regs-override")
		exitCode := 13
		if c.TestConf != nil && c.TestConf.MonitorMode {
			exitCode = 10
		}
		return &policytest.Scenario{
			Name:         "data items reflect probe entry, not earlier assignments",
			Trigger:      policytest.NewCmdTrigger(bin, "ordering", "10", "3", "0").ExpectExitCode(exitCode),
			EventChecker: celRegsChecker(bin, "cel_ordering"),
		}
	}).
	RegisterAtInit()
