// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build amd64 && linux
// +build amd64,linux

package tracing

import (
	"syscall"
	"testing"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/syscallinfo/i386"
	"github.com/cilium/tetragon/pkg/testutils"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	lc "github.com/cilium/tetragon/pkg/matchers/listmatcher"
)

func TestEnforcerOverride32(t *testing.T) {
	testEnforcerCheckSkip(t)

	test := testutils.RepoRootPath("contrib/tester-progs/enforcer-tester-32")
	yaml := NewEnforcerSpecBuilder("enforcer-override").
		WithSyscallList("__ia32_sys_prctl").
		WithMatchBinaries(test).
		WithOverrideValue(-17). // EEXIST
		MustYAML()

	tpChecker := ec.NewProcessTracepointChecker("").
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithSizeArg(i386.SYS_PRCTL),
			)).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_NOTIFYENFORCER)

	checker := ec.NewUnorderedEventChecker(tpChecker)

	checkerFunc := func(_ error, rc int) {
		if rc != int(syscall.EEXIST) {
			t.Fatalf("Wrong exit code %d expected %d", rc, int(syscall.EEXIST))
		}
	}

	testEnforcer(t, yaml, test, "", checker, checkerFunc)
}

func TestEnforcerSignal32(t *testing.T) {
	testEnforcerCheckSkip(t)

	test := testutils.RepoRootPath("contrib/tester-progs/enforcer-tester-32")
	yaml := NewEnforcerSpecBuilder("enforcer-signal").
		WithSyscallList("__ia32_sys_prctl").
		WithMatchBinaries(test).
		WithOverrideValue(-17). // EEXIST
		WithKill(9).            // SigKill
		MustYAML()

	tpChecker := ec.NewProcessTracepointChecker("").
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithSizeArg(i386.SYS_PRCTL),
			)).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_NOTIFYENFORCER)

	checker := ec.NewUnorderedEventChecker(tpChecker)

	checkerFunc := func(err error, _ int) {
		if err == nil || err.Error() != "signal: killed" {
			t.Fatalf("Wrong error '%v' expected 'killed'", err)
		}
	}

	testEnforcer(t, yaml, test, "", checker, checkerFunc)
}

func TestEnforcerOverrideBothBits(t *testing.T) {
	testEnforcerCheckSkip(t)

	test32 := testutils.RepoRootPath("contrib/tester-progs/enforcer-tester-32")
	test64 := testutils.RepoRootPath("contrib/tester-progs/enforcer-tester")

	yaml := NewEnforcerSpecBuilder("enforcer-override").
		WithSyscallList("__ia32_sys_prctl", "sys_prctl").
		WithMatchBinaries(test32, test64).
		WithOverrideValue(-17). // EEXIST
		MustYAML()

	tpChecker32 := ec.NewProcessTracepointChecker("").
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithSizeArg(i386.SYS_PRCTL),
			)).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_NOTIFYENFORCER)

	tpChecker64 := ec.NewProcessTracepointChecker("").
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithSizeArg(syscall.SYS_PRCTL),
			)).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_NOTIFYENFORCER)

	checker := ec.NewUnorderedEventChecker(tpChecker32, tpChecker64)

	checkerFunc := func(_ error, rc int) {
		if rc != int(syscall.EEXIST) {
			t.Fatalf("Wrong exit code %d expected %d", rc, int(syscall.EEXIST))
		}
	}

	testEnforcer(t, yaml, test64, test32, checker, checkerFunc)
}
