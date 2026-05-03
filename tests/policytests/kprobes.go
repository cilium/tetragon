// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tests

import (
	"context"
	"fmt"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	tetragonbtf "github.com/cilium/tetragon/pkg/btf"
	lc "github.com/cilium/tetragon/pkg/matchers/listmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/testutils/policytest"
	"golang.org/x/sys/unix"
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

type algBindTrigger struct {
	algName string
}

func (t *algBindTrigger) Trigger(_ context.Context) error {
	fd, err := unix.Socket(unix.AF_ALG, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		return fmt.Errorf("AF_ALG socket: %w", err)
	}
	defer unix.Close(fd)
	_ = unix.Bind(fd, &unix.SockaddrALG{
		Type: "hash",
		Name: t.algName,
	})
	return nil
}

var _ = policytest.NewBuilder("kprobe-sys-bind-sockaddr-alg").
	WithLabels("kprobes").
	WithParameter(policytest.Parameter{
		Name:    "Hook",
		Default: "kprobes",
		Help:    "hook type for the policy",
	}).
	WithSkip(func(_ *policytest.SkipInfo) string {
		if _, err := tetragonbtf.FindBTFStruct("sockaddr_alg"); err != nil {
			return "sockaddr_alg not found in kernel BTF"
		}
		return ""
	}).
	WithPolicyTemplate(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "sys-bind-sockaddr-alg"
spec:
  {{ .Hook }}:
  - call: "__sys_bind"
    syscall: false
    args:
    - index: 1
      type: "string"
      btfType: "sockaddr_alg"
      resolve: "salg_name"
      user: true
`).AddScenario(func(c *policytest.Conf) *policytest.Scenario {
	const algName = "sha256"
	algChecker := ec.NewProcessKprobeChecker("sys-bind-sockaddr-alg").
		WithFunctionName(sm.Full("__sys_bind")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithStringArg(sm.Full(algName)),
			))
	return &policytest.Scenario{
		Name:         "bind AF_ALG socket and check salg_name",
		Trigger:      &algBindTrigger{algName: algName},
		EventChecker: ec.NewUnorderedEventChecker(algChecker),
	}
}).RegisterAtInit()

var _ = policytest.NewBuilder("kprobe-null-string").WithLabels("kprobes").WithPolicyTemplate(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "kprobe-null-string"
spec:
  kprobes:
  - call: "security_sb_mount"
    syscall: false
    return: true
    args:
      - index: 0 # dev_name
        type: "string"
    returnArg:
      index: 0
      type: "int"
`).AddScenario(func(c *policytest.Conf) *policytest.Scenario {
	myBin := c.TestBinary("null-mount")
	argChecker := ec.NewProcessKprobeChecker("kprobe-null-string").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Full(myBin))).WithArgs(ec.NewKprobeArgumentListMatcher().
		WithOperator(lc.Ordered).
		WithValues(
			ec.NewKprobeArgumentChecker().WithErrorArg(ec.NewKprobeErrorChecker().WithMessage(sm.Full("Bad address"))),
		)).WithReturn(ec.NewKprobeArgumentChecker().WithIntArg(0))

	return &policytest.Scenario{
		Name:         "check null pointer passed for string argument",
		Trigger:      policytest.NewCmdTrigger(myBin).ExpectExitCode(0),
		EventChecker: ec.NewUnorderedEventChecker(argChecker),
	}
}).RegisterAtInit()
