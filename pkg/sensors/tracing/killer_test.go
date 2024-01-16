// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"context"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"testing"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	lc "github.com/cilium/tetragon/pkg/matchers/listmatcher"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/testutils"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func testKiller(t *testing.T, configHook string,
	test string, test2 string,
	checker *eventchecker.UnorderedEventChecker,
	checkerFunc func(err error, rc int)) {

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	err := os.WriteFile(testConfigFile, []byte(configHook), 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	cmd := exec.Command(test)
	err = cmd.Run()

	checkerFunc(err, cmd.ProcessState.ExitCode())

	if test2 != "" {
		cmd := exec.Command(test2)
		err = cmd.Run()

		checkerFunc(err, cmd.ProcessState.ExitCode())
	}

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestKillerOverride(t *testing.T) {
	if !bpf.HasSignalHelper() {
		t.Skip("skipping killer test, bpf_send_signal helper not available")
	}

	test := testutils.RepoRootPath("contrib/tester-progs/getcpu")
	builder := func() *KillerSpecBuilder {
		return NewKillerSpecBuilder("killer-override").
			WithSyscallList("sys_getcpu").
			WithMatchBinaries(test).
			WithOverrideValue(-17) // EEXIST
	}

	tpChecker := ec.NewProcessTracepointChecker("").
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithSizeArg(unix.SYS_GETCPU),
			)).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_NOTIFYKILLER)

	checker := ec.NewUnorderedEventChecker(tpChecker)

	checkerFunc := func(err error, rc int) {
		if rc != int(syscall.EEXIST) {
			t.Fatalf("Wrong exit code %d expected %d", rc, int(syscall.EEXIST))
		}
	}

	t.Run("override_helper", func(t *testing.T) {
		if !bpf.HasOverrideHelper() {
			t.Skip("override_helper not supported")
		}

		t.Run("multi kprobe", func(t *testing.T) {
			if !bpf.HasKprobeMulti() {
				t.Skip("no multi-kprobe support")
			}
			yaml := builder().WithOverrideReturn().WithMultiKprobe().MustYAML()
			testKiller(t, yaml, test, "", checker, checkerFunc)
		})

		t.Run("kprobe (no multi)", func(t *testing.T) {
			yaml := builder().WithOverrideReturn().WithoutMultiKprobe().MustYAML()
			testKiller(t, yaml, test, "", checker, checkerFunc)
		})
	})
	t.Run("fmod_ret", func(t *testing.T) {
		if !bpf.HasModifyReturn() {
			t.Skip("fmod_ret not supported")
		}
		yaml := builder().WithFmodRet().MustYAML()
		testKiller(t, yaml, test, "", checker, checkerFunc)
	})
}

func TestKillerSignal(t *testing.T) {
	if !bpf.HasOverrideHelper() && !bpf.HasModifyReturn() {
		t.Skip("skipping killer test, neither bpf_override_return nor fmod_ret is available")
	}
	if !bpf.HasSignalHelper() {
		t.Skip("skipping killer test, bpf_send_signal helper not available")
	}

	test := testutils.RepoRootPath("contrib/tester-progs/killer-tester")

	tpChecker := ec.NewProcessTracepointChecker("").
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithSizeArg(syscall.SYS_PRCTL),
			)).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_NOTIFYKILLER)

	checker := ec.NewUnorderedEventChecker(tpChecker)

	checkerFunc := func(err error, rc int) {
		if err == nil || err.Error() != "signal: killed" {
			t.Fatalf("Wrong error '%v' expected 'killed'", err)
		}
	}

	builder := func() *KillerSpecBuilder {
		return NewKillerSpecBuilder("killer-signal").
			WithSyscallList("sys_prctl").
			WithMatchBinaries(test).
			WithOverrideValue(-17). // EEXIST
			WithKill(9)             // SigKill
	}

	t.Run("multi kprobe", func(t *testing.T) {
		if !bpf.HasKprobeMulti() {
			t.Skip("no multi-kprobe support")
		}
		if !bpf.HasOverrideHelper() {
			t.Skip("no override helper, so cannot use multi kprobes")
		}

		yaml := builder().WithMultiKprobe().MustYAML()
		testKiller(t, yaml, test, "", checker, checkerFunc)
	})

	t.Run("kprobe (no multi)", func(t *testing.T) {
		yaml := builder().WithoutMultiKprobe().MustYAML()
		testKiller(t, yaml, test, "", checker, checkerFunc)
	})

}

func TestKillerMultiNotSupported(t *testing.T) {
	yaml := NewKillerSpecBuilder("killer-multi").
		WithSyscallList("sys_prctl").
		WithSyscallList("sys_dup").
		WithOverrideValue(-17). // EEXIST
		MustYAML()
	err := checkCrd(t, yaml)
	assert.Error(t, err)
}
