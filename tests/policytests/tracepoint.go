// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tests

import (
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/bpf"
	lc "github.com/cilium/tetragon/pkg/matchers/listmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/testutils/policytest"
)

var _ = policytest.NewBuilder("tracepoint-exec").WithLabels("tracepoint").WithPolicyTemplate(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tracepoint-exec"
spec:
  tracepoints:
  - subsystem: "syscalls"
    event: "sys_enter_execve"
    args:
    - index: 5
      type: "string"
`).AddScenario(func(c *policytest.Conf) *policytest.Scenario {
	nop := c.TestBinary("nop")
	checker := ec.NewProcessTracepointChecker("tracepoint-exec").
		WithSubsys(sm.Full("syscalls")).
		WithEvent(sm.Full("sys_enter_execve")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithStringArg(sm.Full(nop)),
			))

	return &policytest.Scenario{
		Name:         "execute nop and check tracepoint event",
		Trigger:      policytest.NewCmdTrigger(nop),
		EventChecker: ec.NewUnorderedEventChecker(checker),
	}
}).RegisterAtInit()

var _ = policytest.NewBuilder("tracepoint-resolve").WithLabels("tracepoint").WithPolicyTemplate(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tracepoint-resolve"
spec:
  tracepoints:
  - subsystem: "sched"
    event: "sched_process_exec"
    raw: true
    args:
    - index: 2
      type: "file"
      resolve: "file"
`).WithSkip(func(si *policytest.SkipInfo) string {
	if !si.AgentInfo.Probes[bpf.LargeProgsProbe] {
		return "resolve requires kernel support for large programs (v5.3 or newer)"
	}
	return ""
}).AddScenario(func(c *policytest.Conf) *policytest.Scenario {
	nop := c.TestBinary("nop")
	checker := ec.NewProcessTracepointChecker("tracepoint-resolve").
		WithSubsys(sm.Full("sched")).
		WithEvent(sm.Full("sched_process_exec")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithFileArg(ec.NewKprobeFileChecker().WithPath(sm.Full(nop))),
			))
	return &policytest.Scenario{
		Name:         "execute nop and check raw tracepoint event",
		Trigger:      policytest.NewCmdTrigger(nop),
		EventChecker: ec.NewUnorderedEventChecker(checker),
	}
}).RegisterAtInit()
