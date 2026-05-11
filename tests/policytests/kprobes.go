// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tests

import (
	"context"
	"fmt"

	ebtf "github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/bpf"
	lc "github.com/cilium/tetragon/pkg/matchers/listmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/testutils/policytest"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
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
			ec.NewKprobeArgumentChecker().WithErrorArg(ec.NewKprobeErrorChecker().WithMessage(sm.Full("Bad address for basic type"))),
		)).WithReturn(ec.NewKprobeArgumentChecker().WithIntArg(0))

	return &policytest.Scenario{
		Name:         "check null pointer passed for string argument",
		Trigger:      policytest.NewCmdTrigger(myBin).ExpectExitCode(0),
		EventChecker: ec.NewUnorderedEventChecker(argChecker),
	}
}).RegisterAtInit()

const (
	afAlgModuleName = "af_alg"
	afAlgType       = "hash"
	afAlgName       = "sha1"
)

type afAlgBindTrigger struct{}

func (afAlgBindTrigger) Trigger(_ context.Context) error {
	return triggerAFAlgBind()
}

func triggerAFAlgBind() error {
	fd, err := unix.Socket(unix.AF_ALG, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		return fmt.Errorf("socket(AF_ALG): %w", err)
	}
	defer unix.Close(fd)

	if err := unix.Bind(fd, &unix.SockaddrALG{
		Type: afAlgType,
		Name: afAlgName,
	}); err != nil {
		return fmt.Errorf("bind(AF_ALG, %s/%s): %w", afAlgType, afAlgName, err)
	}
	return nil
}

func skipAFAlgBTFTypeModule(_ *policytest.SkipInfo) string {
	if !bpf.HasProgramLargeSize() {
		return "BTF resolve requires large BPF programs"
	}
	if err := triggerAFAlgBind(); err != nil {
		return err.Error()
	}

	spec, err := ebtf.LoadKernelModuleSpec(afAlgModuleName)
	if err != nil {
		return fmt.Sprintf("kernel module BTF for %s is not available: %s", afAlgModuleName, err)
	}

	var st *ebtf.Struct
	if err := spec.TypeByName("sockaddr_alg_new", &st); err != nil {
		return fmt.Sprintf("kernel module BTF type sockaddr_alg_new is not available: %s", err)
	}
	return ""
}

var _ = policytest.NewBuilder("kprobe-btf-type-module-af-alg-bind").
	WithLabels("kprobes").
	WithSkip(skipAFAlgBTFTypeModule).
	WithPolicyTemplate(fmt.Sprintf(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "btf-type-module-af-alg"
spec:
  kprobes:
  - call: "security_socket_bind"
    syscall: false
    args:
    - index: 1
      type: "uint16"
      label: "sockaddr_alg.salg_family"
      btfType: "sockaddr_alg_new"
      btfTypeModule: "%s"
      resolve: "salg_family"
    - index: 1
      type: "string"
      label: "sockaddr_alg.salg_type"
      btfType: "sockaddr_alg_new"
      btfTypeModule: "%s"
      resolve: "salg_type"
    - index: 1
      type: "string"
      label: "sockaddr_alg.salg_name"
      btfType: "sockaddr_alg_new"
      btfTypeModule: "%s"
      resolve: "salg_name"
`, afAlgModuleName, afAlgModuleName, afAlgModuleName)).
	AddScenario(func(_ *policytest.Conf) *policytest.Scenario {
		checker := ec.NewProcessKprobeChecker("").
			WithFunctionName(sm.Full("security_socket_bind")).
			WithProcess(ec.NewProcessChecker().
				WithBinary(sm.Suffix(tus.Conf().SelfBinary))).
			WithArgs(ec.NewKprobeArgumentListMatcher().
				WithOperator(lc.Ordered).
				WithValues(
					ec.NewKprobeArgumentChecker().
						WithUintArg(unix.AF_ALG).
						WithLabel(sm.Full("sockaddr_alg.salg_family")),
					ec.NewKprobeArgumentChecker().
						WithStringArg(sm.Full(afAlgType)).
						WithLabel(sm.Full("sockaddr_alg.salg_type")),
					ec.NewKprobeArgumentChecker().
						WithStringArg(sm.Full(afAlgName)).
						WithLabel(sm.Full("sockaddr_alg.salg_name")),
				))

		return &policytest.Scenario{
			Name:         "bind AF_ALG socket and check sockaddr_alg BTF module fields",
			Trigger:      afAlgBindTrigger{},
			EventChecker: ec.NewUnorderedEventChecker(checker),
		}
	}).RegisterAtInit()
