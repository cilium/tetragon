// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tests

import (
	"fmt"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/config"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/testutils/policytest"
)

var _ = policytest.NewBuilder("kprobe-match-parent-binaries-combined").
	WithLabels("kprobes").
	WithSkip(func(_ *policytest.SkipInfo) string {
		if !config.EnableLargeProgs() {
			return "kernels without large progs do not support matchParentBinaries selector"
		}
		return ""
	}).
	WithSetup(func() func() {
		option.Config.ParentsMapEnabled = true
		return func() { option.Config.ParentsMapEnabled = false }
	}).
	WithAllEvents().
	WithPolicyTemplate(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "match-parent-binaries-test"
spec:
  kprobes:
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
      matchParentBinaries:
      - operator: In
        values:
        - /usr/bin/bash
`).
	AddScenario(func(c *policytest.Conf) *policytest.Scenario {
		lseekBin := c.TestBinary("lseek-pipe")
		// Feeding commands to bash via piped stdin forces it to fork a child,
		// so lseek-pipe's parent binary is /usr/bin/bash — matching the selector.
		trigger := fmt.Sprintf("echo '%s -1 0 4444' | /usr/bin/bash", lseekBin)
		lseekChecker := ec.NewProcessKprobeChecker("lseek-parent-checker").
			WithFunctionName(sm.Suffix("sys_lseek")).
			WithProcess(ec.NewProcessChecker().WithBinary(sm.Full(lseekBin)))
		return &policytest.Scenario{
			Name:         "execute lseek-pipe via bash parent and check events",
			Trigger:      policytest.NewCmdTrigger("/usr/bin/bash", "-c", trigger),
			EventChecker: ec.NewUnorderedEventChecker(lseekChecker),
		}
	}).
	AddScenario(func(c *policytest.Conf) *policytest.Scenario {
		lseekBin := c.TestBinary("lseek-pipe")
		// sh's parent is not /usr/bin/bash so the selector drops all events.
		// The checker describes events that would arrive if the filter were
		// broken; ExpectCheckerFailure: true asserts they do not.
		lseekChecker := ec.NewProcessKprobeChecker("lseek-parent-checker").
			WithFunctionName(sm.Suffix("sys_lseek")).
			WithProcess(ec.NewProcessChecker().WithBinary(sm.Full(lseekBin)))
		return &policytest.Scenario{
			Name:                 "execute lseek-pipe via sh parent and check no events",
			Trigger:              policytest.NewCmdTrigger("/usr/bin/sh", "-c", lseekBin+" -1 0 4444"),
			EventChecker:         ec.NewUnorderedEventChecker(lseekChecker),
			ExpectCheckerFailure: true,
		}
	}).
	RegisterAtInit()

// followChildren not firing for a descendant whose own most recent exec was
// a same-process re-exec rather than a fork+exec).
var _ = policytest.NewBuilder("kprobe-match-parent-binaries-followchildren-combined").
	WithLabels("kprobes").
	WithSkip(func(_ *policytest.SkipInfo) string {
		if !config.EnableLargeProgs() {
			return "kernels without large progs do not support matchParentBinaries selector"
		}
		return ""
	}).
	WithSetup(func() func() {
		option.Config.ParentsMapEnabled = true
		return func() { option.Config.ParentsMapEnabled = false }
	}).
	WithAllEvents().
	WithPolicyTemplate(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "match-parent-binaries-followchildren-test"
spec:
  kprobes:
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
      matchParentBinaries:
      - operator: In
        values:
        - /usr/bin/bash
        followChildren: true
`).
	AddScenario(func(c *policytest.Conf) *policytest.Scenario {
		lseekBin := c.TestBinary("lseek-pipe")
		// The pipe forces bash to fork a child. That child's first exec (via
		// the "exec" builtin) replaces it with sh -- a fork+exec transition
		// with the clone flag set. sh's own "-c" script is a single command
		// with no pipe/redirection, so sh applies its own exec optimization
		// and self-execs (no fork) directly into lseek-pipe. So the process
		// that finally triggers sys_lseek had its *last* exec not preceded
		// by a fork, several hops below the /usr/bin/bash ancestor that
		// followChildren is supposed to keep matching against.
		trigger := fmt.Sprintf(`echo 'exec /usr/bin/sh -c "%s -1 0 4444"' | /usr/bin/bash`, lseekBin)
		lseekChecker := ec.NewProcessKprobeChecker("lseek-followchildren-checker").
			WithFunctionName(sm.Suffix("sys_lseek")).
			WithProcess(ec.NewProcessChecker().WithBinary(sm.Full(lseekBin)))
		return &policytest.Scenario{
			Name:         "fork+exec then self-exec descendant of bash still matches with followChildren",
			Trigger:      policytest.NewCmdTrigger("/usr/bin/bash", "-c", trigger),
			EventChecker: ec.NewUnorderedEventChecker(lseekChecker),
		}
	}).
	RegisterAtInit()
