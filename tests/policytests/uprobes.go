// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tests

import (
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/testutils/policytest"
)

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
	if !si.AgentInfo.Probes["uprobe_regs_change"] {
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
