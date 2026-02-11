// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tests

import (
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/testutils/policytest"
)

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
