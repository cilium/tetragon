// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tests

import (
	"github.com/cilium/tetragon/pkg/bpf"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	lc "github.com/cilium/tetragon/pkg/matchers/listmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/testutils/policytest"
)

// This file contains tests on lsm hooks

var _ = policytest.NewBuilder("lsm-dup-hooks").WithLabels("lsm").WithPolicyTemplate(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "lsm-dup-hooks"
spec:
  lsmhooks:
  - hook: "file_open"
    args:
      - index: 0
        type: "file"
    selectors:
    - matchArgs:
      - args: [0]
        operator: "Equal"
        values: [{{ tempFile "file1"}}]
      matchActions:
        - action: Post
  - hook: "file_open"
    args:
      - index: 0
        type: "file"
    selectors:
    - matchArgs:
      - args: [0]
        operator: "Equal"
        values: [{{ tempFile "file2" }}]
      matchActions:
        - action: Post
`).WithSkip(func(si *policytest.SkipInfo) string {
	if !si.AgentInfo.Probes[bpf.LargeProgsProbe] {
		return "need 5.3 or newer kernel"
	}
	if !si.AgentInfo.Probes[bpf.LsmProbe] {
		return "Need LSM Support"
	}
	return ""
}).AddScenario(func(c *policytest.Conf) *policytest.Scenario {
	myBin := c.TestBinary("direct-write-tester")
	tempFile := c.TempFileMust("file1")
	fileChecker := ec.NewProcessLsmChecker("lsm-file1-checker").
		WithFunctionName(sm.Suffix("file_open")).
		WithProcess(ec.NewProcessChecker().WithBinary(sm.Full(myBin))).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithFileArg(ec.NewKprobeFileChecker().WithPath(sm.Full(tempFile)))))

	return &policytest.Scenario{
		Name:         "checking first lsm hook event fired for duplicate hook policy",
		Trigger:      policytest.NewCmdTrigger(myBin, tempFile).ExpectExitCode(0),
		EventChecker: ec.NewUnorderedEventChecker(fileChecker),
	}
}).AddScenario(func(c *policytest.Conf) *policytest.Scenario {
	myBin := c.TestBinary("direct-write-tester")
	tempFile := c.TempFileMust("file2")
	fileChecker := ec.NewProcessLsmChecker("lsm-file2-checker").
		WithFunctionName(sm.Suffix("file_open")).
		WithProcess(ec.NewProcessChecker().WithBinary(sm.Full(myBin))).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithFileArg(ec.NewKprobeFileChecker().WithPath(sm.Full(tempFile)))))

	return &policytest.Scenario{
		Name:         "checking second lsm hook event fired for duplicate hook policy",
		Trigger:      policytest.NewCmdTrigger(myBin, tempFile).ExpectExitCode(0),
		EventChecker: ec.NewUnorderedEventChecker(fileChecker),
	}
}).RegisterAtInit()
