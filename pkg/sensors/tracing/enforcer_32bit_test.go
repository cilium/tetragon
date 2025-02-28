// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"runtime"
	"syscall"
	"testing"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	lc "github.com/cilium/tetragon/pkg/matchers/listmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/syscallinfo/arm32"
	"github.com/cilium/tetragon/pkg/syscallinfo/i386"
	"github.com/cilium/tetragon/pkg/testutils"
)

func TestEnforcerOverride32(t *testing.T) {
	testEnforcerCheckSkip(t)

	prctlID := uint64(0)
	var syscallVal string
	sysIDChecker := ec.NewSyscallIdChecker()
	switch a := runtime.GOARCH; a {
	case "amd64":
		syscallVal = "i386/sys_prctl"
		prctlID = i386.SYS_PRCTL
		sysIDChecker = sysIDChecker.WithId(uint32(prctlID)).WithAbi(sm.Full("i386"))
	case "arm64":
		syscallVal = "arm32/sys_prctl"
		prctlID = arm32.SYS_PRCTL
		sysIDChecker = sysIDChecker.WithId(uint32(prctlID)).WithAbi(sm.Full("arm32"))
	default:
		t.Fatalf("Unknown arch: %s", a)
	}

	test := testutils.RepoRootPath("contrib/tester-progs/enforcer-tester-32")
	yaml := NewEnforcerSpecBuilder("enforcer-override").
		WithSyscallList(syscallVal).
		WithMatchBinaries(test).
		WithOverrideValue(-17). // EEXIST
		MustYAML()

	tpChecker := ec.NewProcessTracepointChecker("").
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithSyscallId(sysIDChecker),
			)).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_NOTIFYENFORCER)

	checker := ec.NewUnorderedEventChecker(tpChecker)

	checkerFuncErr := func(t *testing.T, _ error, rc int) {
		if rc != int(syscall.EEXIST) {
			t.Fatalf("Wrong exit code %d expected %d", rc, int(syscall.EEXIST))
		}
	}
	testEnforcer(t, yaml, checker, newCmdChecker(test, checkerFuncErr))
}

func TestEnforcerSignal32(t *testing.T) {
	testEnforcerCheckSkip(t)

	prctlID := uint64(0)
	var syscallVal string
	sysIDChecker := ec.NewSyscallIdChecker()
	switch a := runtime.GOARCH; a {
	case "amd64":
		syscallVal = "i386/sys_prctl"
		prctlID = i386.SYS_PRCTL
		sysIDChecker = sysIDChecker.WithId(uint32(prctlID)).WithAbi(sm.Full("i386"))
	case "arm64":
		syscallVal = "arm32/sys_prctl"
		prctlID = arm32.SYS_PRCTL
		sysIDChecker = sysIDChecker.WithId(uint32(prctlID)).WithAbi(sm.Full("arm32"))
	default:
		t.Fatalf("Unknown arch: %s", a)
	}

	test := testutils.RepoRootPath("contrib/tester-progs/enforcer-tester-32")
	yaml := NewEnforcerSpecBuilder("enforcer-signal").
		WithSyscallList(syscallVal).
		WithMatchBinaries(test).
		WithOverrideValue(-17). // EEXIST
		WithKill(9).            // SigKill
		MustYAML()

	tpChecker := ec.NewProcessTracepointChecker("").
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithSyscallId(sysIDChecker),
			)).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_NOTIFYENFORCER)

	checker := ec.NewUnorderedEventChecker(tpChecker)

	checkerFunc := func(t *testing.T, err error, _ int) {
		if err == nil || err.Error() != "signal: killed" {
			t.Fatalf("Wrong error '%v' expected 'killed'", err)
		}
	}

	testEnforcer(t, yaml, checker, newCmdChecker(test, checkerFunc))
}

func TestEnforcerOverrideBothBits(t *testing.T) {
	testEnforcerCheckSkip(t)

	prctlID := uint64(0)
	var syscallVal string
	sysIDChecker32 := ec.NewSyscallIdChecker()
	switch a := runtime.GOARCH; a {
	case "amd64":
		syscallVal = "i386/sys_prctl"
		prctlID = i386.SYS_PRCTL
		sysIDChecker32 = sysIDChecker32.WithId(uint32(prctlID)).WithAbi(sm.Full("i386"))
	case "arm64":
		syscallVal = "arm32/sys_prctl"
		prctlID = arm32.SYS_PRCTL
		sysIDChecker32 = sysIDChecker32.WithId(uint32(prctlID)).WithAbi(sm.Full("arm32"))
	default:
		t.Fatalf("Unknown arch: %s", a)
	}

	test32 := testutils.RepoRootPath("contrib/tester-progs/enforcer-tester-32")
	test64 := testutils.RepoRootPath("contrib/tester-progs/enforcer-tester")

	yaml := NewEnforcerSpecBuilder("enforcer-override").
		WithSyscallList(syscallVal, "sys_prctl").
		WithMatchBinaries(test32, test64).
		WithOverrideValue(-17). // EEXIST
		MustYAML()

	tpChecker32 := ec.NewProcessTracepointChecker("").
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithSyscallId(sysIDChecker32),
			)).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_NOTIFYENFORCER)

	tpChecker64 := ec.NewProcessTracepointChecker("").
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithSyscallId(mkSysIDChecker(t, syscall.SYS_PRCTL)),
			)).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_NOTIFYENFORCER)

	checker := ec.NewUnorderedEventChecker(tpChecker32, tpChecker64)

	checkerFunc := func(t *testing.T, _ error, rc int) {
		if rc != int(syscall.EEXIST) {
			t.Fatalf("Wrong exit code %d expected %d", rc, int(syscall.EEXIST))
		}
	}

	testEnforcer(t, yaml, checker, newCmdChecker(test64, checkerFunc), newCmdChecker(test32, checkerFunc))
}
