// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tests

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	ebtf "github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/bpf"
	bc "github.com/cilium/tetragon/pkg/matchers/bytesmatcher"
	lc "github.com/cilium/tetragon/pkg/matchers/listmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	tpath "github.com/cilium/tetragon/pkg/reader/path"
	"github.com/cilium/tetragon/pkg/testutils/policytest"
)

// This file contains tests on kernel functions.

var _ = policytest.NewBuilder("kprobe-lseek").WithLabels("kprobes").
	WithParameter(policytest.Parameter{
		Name:    "Hook",
		Default: "kprobes",
		Values:  []any{"kprobes", "fentries"},
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

type fdWriteTrigger struct {
	dir  string
	path string
}

func (t *fdWriteTrigger) Trigger(_ context.Context) error {
	defer os.RemoveAll(t.dir)

	file, err := os.OpenFile(t.path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return fmt.Errorf("open fd target: %w", err)
	}
	defer file.Close()

	if _, err := file.WriteString("hello fd\n"); err != nil {
		return fmt.Errorf("write fd target: %w", err)
	}
	return nil
}

var _ = policytest.NewBuilder("kprobe-fd-arg").
	WithLabels("kprobes").
	WithParameter(policytest.Parameter{
		Name:    "Hook",
		Default: "kprobes",
		Help:    "type of hook to use in the policy",
	}).WithPolicyTemplate(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "kprobe-fd-arg"
spec:
  {{ .Hook }}:
  - call: "sys_write"
    syscall: true
    args:
    - index: 0
      type: "fd"
    - index: 1
      type: "char_buf"
      sizeArgIndex: 3
    - index: 2
      type: "size_t"
    selectors:
    - matchArgs:
      - operator: Postfix
        index: 0
        values:
        - "/target"
`).AddScenario(func(_ *policytest.Conf) *policytest.Scenario {
	dir, err := os.MkdirTemp("", "kprobe-fd-arg")
	if err != nil {
		return &policytest.Scenario{
			Name:    "failed to create temp dir",
			Trigger: policytest.NewCmdTrigger("/usr/bin/false"),
		}
	}
	filePath := filepath.Join(dir, "target")
	if err := os.WriteFile(filePath, []byte{}, 0644); err != nil {
		os.RemoveAll(dir)
		return &policytest.Scenario{
			Name:    "failed to create temp file",
			Trigger: policytest.NewCmdTrigger("/usr/bin/false"),
		}
	}
	st, err := os.Stat(filePath)
	if err != nil {
		os.RemoveAll(dir)
		return &policytest.Scenario{
			Name:    "failed to stat temp file",
			Trigger: policytest.NewCmdTrigger("/usr/bin/false"),
		}
	}
	permission := tpath.FilePathModeToStr(uint16(st.Mode() | syscall.S_IFREG))

	checker := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Suffix("sys_write")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithFileArg(ec.NewKprobeFileChecker().
					WithPath(sm.Full(filePath)).
					WithPermission(sm.Full(permission)),
				),
				ec.NewKprobeArgumentChecker().WithBytesArg(bc.Full([]byte("hello fd\n"))),
				ec.NewKprobeArgumentChecker().WithSizeArg(9),
			))

	return &policytest.Scenario{
		Name:         "file retrieval through fd type",
		Trigger:      &fdWriteTrigger{dir: dir, path: filePath},
		EventChecker: ec.NewUnorderedEventChecker(checker),
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
				WithBinary(sm.Suffix(filepath.Base(os.Args[0])))).
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

func skipSubStringKfunc(si *policytest.SkipInfo) string {
	if !si.AgentInfo.Probes[bpf.SubStringKfuncProbe] {
		return "SubString operator requires bpf_strnstr kfunc and large BPF programs"
	}
	return ""
}

var _ = policytest.NewBuilder("kprobe-substring-linux-binprm").
	WithLabels("kprobes").
	WithSkip(skipSubStringKfunc).
	WithParameter(policytest.Parameter{
		Name:    "Hook",
		Default: "kprobes",
		Help:    "type of hook to use in the policy",
	}).
	WithPolicyTemplate(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "substring-linux-binprm"
spec:
  {{ .Hook }}:
  - call: "security_bprm_check"
    syscall: false
    args:
    - index: 0
      type: "linux_binprm"
    selectors:
    - matchArgs:
      - operator: SubString
        index: 0
        values:
        - "/i"
`).AddScenario(func(_ *policytest.Conf) *policytest.Scenario {
	checker := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full("security_bprm_check")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithLinuxBinprmArg(ec.NewKprobeLinuxBinprmChecker().WithPath(sm.Suffix("/id"))),
			))

	return &policytest.Scenario{
		Name:         "SubString filter on linux_binprm matches /usr/bin/id",
		Trigger:      policytest.NewCmdTrigger("/usr/bin/id"),
		EventChecker: ec.NewUnorderedEventChecker(checker),
	}
}).RegisterAtInit()

var _ = policytest.NewBuilder("kprobe-substring-file").
	WithLabels("kprobes").
	WithSkip(skipSubStringKfunc).
	WithParameter(policytest.Parameter{
		Name:    "Hook",
		Default: "kprobes",
		Help:    "type of hook to use in the policy",
	}).
	WithPolicyTemplate(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "substring-file"
spec:
  {{ .Hook }}:
  - call: "security_file_open"
    syscall: false
    args:
    - index: 0
      type: "file"
    selectors:
    - matchArgs:
      - operator: SubString
        index: 0
        values:
        - "/i"
`).AddScenario(func(_ *policytest.Conf) *policytest.Scenario {
	checker := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full("security_file_open")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithFileArg(ec.NewKprobeFileChecker().WithPath(sm.Suffix("/id"))),
			))

	return &policytest.Scenario{
		Name:         "SubString filter on file type matches /usr/bin/id",
		Trigger:      policytest.NewCmdTrigger("/usr/bin/id"),
		EventChecker: ec.NewUnorderedEventChecker(checker),
	}
}).RegisterAtInit()

type triggerSubStringPath struct{}

func (t *triggerSubStringPath) Trigger(context context.Context) error {
	tmpDir, err := os.MkdirTemp("", "substring-path-test")
	if err != nil {
		return nil
	}
	defer os.RemoveAll(tmpDir)
	testDir := tmpDir + "/match_id_test/inner_dir"
	return policytest.NewCmdTrigger("/usr/bin/mkdir", "-p", testDir).Trigger(context)
}

var _ = policytest.NewBuilder("kprobe-substring-path").
	WithLabels("kprobes").
	WithSkip(skipSubStringKfunc).
	WithParameter(policytest.Parameter{
		Name:    "Hook",
		Default: "kprobes",
		Help:    "type of hook to use in the policy",
	}).
	WithPolicyTemplate(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "substring-path"
spec:
  {{ .Hook }}:
  - call: "security_path_mkdir"
    syscall: false
    args:
    - index: 0
      type: "path"
    selectors:
    - matchArgs:
      - operator: SubString
        index: 0
        values:
        - "_id_"
`).AddScenario(func(_ *policytest.Conf) *policytest.Scenario {
	checker := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full("security_path_mkdir")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithPathArg(ec.NewKprobePathChecker().WithPath(sm.Suffix("match_id_test"))),
			))

	return &policytest.Scenario{
		Name:         "SubString filter on path type matches directory with _id_ in name",
		Trigger:      &triggerSubStringPath{},
		EventChecker: ec.NewUnorderedEventChecker(checker),
	}
}).RegisterAtInit()
