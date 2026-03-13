// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tests

import (
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/testutils/policytest"
)

// This file contains tests on kernel functions.

var _ = policytest.NewBuilder("kprobe-lseek").WithLabels("kprobes").
	WithParameter(policytest.Parameter{
		Name:    "Hook",
		Default: "kprobes",
		Help:    "type of hook to use in the policy",
	}).WithPolicyTemplate(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "lseek-test"
spec:
  {{ .Hook }}:
  - call: "sys_lseek"
    return: false
    syscall: true
    args:
    - index: 0
      type: "int"
    selectors:
    - matchBinaries:
      - operator: In
        values:
        - {{ testBinary "lseek-pipe" }}
`).AddScenario(func(c *policytest.Conf) *policytest.Scenario {
	lseek := c.TestBinary("lseek-pipe")
	lseekChecker := ec.NewProcessKprobeChecker("lseek-checker").WithFunctionName(sm.Suffix("sys_lseek"))
	return &policytest.Scenario{
		Name:         "execute lseek and check events",
		Trigger:      policytest.NewCmdTrigger(lseek, "-1", "0", "4444"),
		EventChecker: ec.NewUnorderedEventChecker(lseekChecker),
	}
}).RegisterAtInit()
