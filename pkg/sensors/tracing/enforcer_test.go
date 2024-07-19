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
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/arch"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/kernels"
	lc "github.com/cilium/tetragon/pkg/matchers/listmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/base"
	"github.com/cilium/tetragon/pkg/testutils"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func testEnforcerCheckSkip(t *testing.T) {
	if !bpf.HasSignalHelper() {
		t.Skip("skipping enforcer test, bpf_send_signal helper not available")
	}
	if !bpf.HasOverrideHelper() && !bpf.HasModifyReturnSyscall() {
		t.Skip("skipping test, neither bpf_override_return nor fmod_ret for syscalls is available")
	}
}

func testEnforcer(t *testing.T, configHook string,
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

func TestEnforcerOverride(t *testing.T) {
	testEnforcerCheckSkip(t)

	test := testutils.RepoRootPath("contrib/tester-progs/getcpu")
	builder := func() *EnforcerSpecBuilder {
		return NewEnforcerSpecBuilder("enforcer-override").
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
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_NOTIFYENFORCER)

	checker := ec.NewUnorderedEventChecker(tpChecker)

	checkerFunc := func(_ error, rc int) {
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
			testEnforcer(t, yaml, test, "", checker, checkerFunc)
		})

		t.Run("kprobe (no multi)", func(t *testing.T) {
			yaml := builder().WithOverrideReturn().WithoutMultiKprobe().MustYAML()
			testEnforcer(t, yaml, test, "", checker, checkerFunc)
		})
	})
	t.Run("fmod_ret", func(t *testing.T) {
		if !bpf.HasModifyReturn() {
			t.Skip("fmod_ret not supported")
		}
		yaml := builder().WithFmodRet().MustYAML()
		testEnforcer(t, yaml, test, "", checker, checkerFunc)
	})
}

func TestEnforcerOverrideManySyscalls(t *testing.T) {
	testEnforcerCheckSkip(t)

	test := testutils.RepoRootPath("contrib/tester-progs/getcpu")
	builder := func() *EnforcerSpecBuilder {
		return NewEnforcerSpecBuilder("enforcer-override").
			WithSyscallList("sys_getcpu", "sys_sethostname").
			WithMatchBinaries(test).
			WithOverrideValue(-17) // EEXIST
	}

	tpChecker := ec.NewProcessTracepointChecker("").
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithSizeArg(unix.SYS_GETCPU),
			)).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_NOTIFYENFORCER)

	checker := ec.NewUnorderedEventChecker(tpChecker)

	checkerFunc := func(_ error, rc int) {
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
			testEnforcer(t, yaml, test, "", checker, checkerFunc)
		})

		t.Run("kprobe (no multi)", func(t *testing.T) {
			yaml := builder().WithOverrideReturn().WithoutMultiKprobe().MustYAML()
			testEnforcer(t, yaml, test, "", checker, checkerFunc)
		})
	})
	t.Run("fmod_ret", func(t *testing.T) {
		if !bpf.HasModifyReturn() {
			t.Skip("fmod_ret not supported")
		}
		yaml := builder().WithFmodRet().MustYAML()
		testEnforcer(t, yaml, test, "", checker, checkerFunc)
	})
}

func TestEnforcerSignal(t *testing.T) {
	testEnforcerCheckSkip(t)

	test := testutils.RepoRootPath("contrib/tester-progs/enforcer-tester")

	tpChecker := ec.NewProcessTracepointChecker("").
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithSizeArg(syscall.SYS_PRCTL),
			)).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_NOTIFYENFORCER)

	checker := ec.NewUnorderedEventChecker(tpChecker)

	checkerFunc := func(err error, _ int) {
		if err == nil || err.Error() != "signal: killed" {
			t.Fatalf("Wrong error '%v' expected 'killed'", err)
		}
	}

	builder := func() *EnforcerSpecBuilder {
		return NewEnforcerSpecBuilder("enforcer-signal").
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
		testEnforcer(t, yaml, test, "", checker, checkerFunc)
	})

	t.Run("kprobe (no multi)", func(t *testing.T) {
		yaml := builder().WithoutMultiKprobe().MustYAML()
		testEnforcer(t, yaml, test, "", checker, checkerFunc)
	})

}

func TestEnforcerMultiNotSupported(t *testing.T) {
	yaml := NewEnforcerSpecBuilder("enforcer-multi").
		WithSyscallList("sys_prctl").
		WithSyscallList("sys_dup").
		WithOverrideValue(-17). // EEXIST
		MustYAML()
	err := checkCrd(t, yaml)
	assert.Error(t, err)
}

func testSecurity(t *testing.T, tracingPolicy, tempFile string) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	createCrdFile(t, tracingPolicy)

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile,
		tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	testBin := testutils.RepoRootPath("contrib/tester-progs/direct-write-tester")

	cmd := exec.Command(testBin, tempFile)
	err = cmd.Run()
	assert.Error(t, err)

	t.Logf("Running: %s %v\n", cmd.String(), err)

	kpCheckerPwrite := ec.NewProcessKprobeChecker("").
		WithProcess(ec.NewProcessChecker().
			WithBinary(sm.Suffix(testBin))).
		WithFunctionName(sm.Full(arch.AddSyscallPrefixTestHelper(t, "sys_pwrite64"))).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_NOTIFYENFORCER).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithFileArg(
					ec.NewKprobeFileChecker().WithPath(sm.Full(tempFile))),
			))

	checker := ec.NewUnorderedEventChecker(kpCheckerPwrite)
	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)

	// check the pwrite syscall did not write anything
	fileInfo, err := os.Stat(tempFile)
	if assert.NoError(t, err) {
		assert.NotEqual(t, 0, fileInfo.Size())
	}
}

func directWriteTempFile(t *testing.T) string {
	// We can't use t.TempDir as it writes into /tmp by default.
	// The direct-write-tester.c program opens and writes using the O_DIRECT
	// flag that is unsupported and return EINVAL on tmpfs, while it works on a
	// disk based fs. Recently, the base image used by vmtests started to switch
	// /tmp from the disk to tmpfs which made that test fail.
	tempFile, err := os.CreateTemp("/var/tmp", "tetragon-testfile-*")
	if err != nil {
		t.Fatalf("failed to create temporary file for tester prog: %s", err)
	}
	t.Cleanup(func() {
		os.Remove(tempFile.Name())
	})
	return tempFile.Name()
}

// Testing the ability to kill the process before it executes the syscall,
// in this case direct pwrite syscall.
// Standard Sigkill action kills executed from sys_pwrite probe kills the
// process, but only after the pwrite syscall is executed.
// Now we can mitigate that by attaching enforcer to security_file_permission
// function and override its return value to prevent the pwrite syscall
// execution.
//
// The testing spec below:
// - attaches probe to pwrite
// - attaches enforcer to security_file_permission
// - executes SigKill action for attempted pwrite to specific file
// - executes NotifyEnforcer action to instruct enforcer to override the
//   security_file_permission return value with -1
// - tests that no data got written to the monitored file

func TestEnforcerSecuritySigKill(t *testing.T) {
	if !bpf.HasSignalHelper() {
		t.Skip("skipping enforcer test, bpf_send_signal helper not available")
	}

	if !bpf.HasModifyReturn() {
		t.Skip("skipping enforcer test, fmod_ret is not available")
	}

	if !kernels.EnableLargeProgs() {
		t.Skip("Older kernels do not support matchArgs for more than one arguments")
	}

	tempFile := directWriteTempFile(t)

	tracingPolicy := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "syswritefollowfdpsswd"
spec:
  options:
    - name: "override-method"
      value: "fmod-ret"
  enforcers:
  - calls:
    - "security_file_permission"
  kprobes:
  - call: "fd_install"
    syscall: false
    args:
    - index: 0
      type: int
    - index: 1
      type: "file"
    selectors:
    - matchArgs:
      - index: 1
        operator: "Equal"
        values:
        - "` + tempFile + `"
      matchActions:
      - action: FollowFD
        argFd: 0
        argName: 1
  - call: "sys_close"
    syscall: true
    args:
    - index: 0
      type: "int"
    selectors:
    - matchActions:
      - action: UnfollowFD
        argFd: 0
        argName: 0
  - call: "sys_pwrite64"
    syscall: true
    args:
    - index: 0
      type: "fd"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Equal"
        values:
        - "` + tempFile + `"
      matchActions:
      - action: Sigkill
      - action: "NotifyEnforcer"
        argError: -1
`

	testSecurity(t, tracingPolicy, tempFile)
}

// Testing the ability to kill the process before it executes the syscall,
// in similar way as in TestEnforcerSecuritySigKill test.
// The only difference is we use the NotifyEnforcer to send the signal instead
// of using SigKill action.
//
// The testing spec below:
// - attaches probe to pwrite
// - attaches enforcer to security_file_permission
// - executes NotifyEnforcer to instruct enforcer to send sigkill to current process
//   and override the security_file_permission return value with -1
// - tests that no data got written to the monitored file

func TestEnforcerSecurityNotifyEnforcer(t *testing.T) {
	if !bpf.HasSignalHelper() {
		t.Skip("skipping enforcer test, bpf_send_signal helper not available")
	}

	if !bpf.HasModifyReturn() {
		t.Skip("skipping enforcer test, fmod_ret is not available")
	}

	if !kernels.EnableLargeProgs() {
		t.Skip("Older kernels do not support matchArgs for more than one arguments")
	}

	tempFile := directWriteTempFile(t)

	tracingPolicy := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "syswritefollowfdpsswd"
spec:
  options:
    - name: "override-method"
      value: "fmod-ret"
  enforcers:
  - calls:
    - "security_file_permission"
  kprobes:
  - call: "fd_install"
    syscall: false
    args:
    - index: 0
      type: int
    - index: 1
      type: "file"
    selectors:
    - matchArgs:
      - index: 1
        operator: "Equal"
        values:
        - "` + tempFile + `"
      matchActions:
      - action: FollowFD
        argFd: 0
        argName: 1
  - call: "sys_close"
    syscall: true
    args:
    - index: 0
      type: "int"
    selectors:
    - matchActions:
      - action: UnfollowFD
        argFd: 0
        argName: 0
  - call: "sys_pwrite64"
    syscall: true
    args:
    - index: 0
      type: "fd"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Equal"
        values:
        - "` + tempFile + `"
      matchActions:
      - action: "NotifyEnforcer"
        argError: -1
        argSig: 9
`

	testSecurity(t, tracingPolicy, tempFile)
}

// This test loads 2 policies:
// - first set standard enforcer tracepoint setup on sys_prctl
//   with first argument value 0xffff
// - second set standard enforcer tracepoint setup on sys_prctl
//   with first argument value 0xfffe
// then make sure both policies catch and kill.

func TestEnforcerMulti(t *testing.T) {
	if !bpf.HasSignalHelper() {
		t.Skip("skipping enforcer test, bpf_send_signal helper not available")
	}

	if !bpf.HasModifyReturn() {
		t.Skip("skipping enforcer test, fmod_ret is not available")
	}

	if !kernels.EnableLargeProgs() {
		t.Skip("Older kernels do not support matchArgs for more than one arguments")
	}

	testBin := testutils.RepoRootPath("contrib/tester-progs/enforcer-tester")

	policyYAML1 := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "enforcer-prctl-1"
spec:
  lists:
  - name: "prctl"
    type: "syscalls"
    values:
    - "sys_prctl"
  enforcers:
  - calls:
    - "list:prctl"
  tracepoints:
  - subsystem: "raw_syscalls"
    event: "sys_enter"
    args:
    - index: 4
      type: "syscall64"
    - index: 5
      type: "int64"
    selectors:
    - matchArgs:
      - index: 0
        operator: "InMap"
        values:
        - "list:prctl"
      - index: 1
        operator: "Equal"
        values:
        - 0xffff
      matchBinaries:
      - operator: "In"
        values:
        - "` + testBin + `"
      matchActions:
      - action: "NotifyEnforcer"
        argError: -1
        argSig: 9
`

	policyYAML2 := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "enforcer-prctl-2"
spec:
  lists:
  - name: "prctl"
    type: "syscalls"
    values:
    - "sys_prctl"
  enforcers:
  - calls:
    - "list:prctl"
  tracepoints:
  - subsystem: "raw_syscalls"
    event: "sys_enter"
    args:
    - index: 4
      type: "syscall64"
    - index: 5
      type: "int64"
    selectors:
    - matchArgs:
      - index: 0
        operator: "InMap"
        values:
        - "list:prctl"
      - index: 1
        operator: "Equal"
        values:
        - 0xfffe
      matchBinaries:
      - operator: "In"
        values:
        - "` + testBin + `"
      matchActions:
      - action: "NotifyEnforcer"
        argError: -1
        argSig: 9
`

	policy1, err := tracingpolicy.FromYAML(policyYAML1)
	if err != nil {
		t.Errorf("FromYAML policyYAML1 error %s", err)
	}

	policy2, err := tracingpolicy.FromYAML(policyYAML2)
	if err != nil {
		t.Errorf("FromYAML policyYAML2 error %s", err)
	}

	if err := observer.InitDataCache(1024); err != nil {
		t.Fatalf("observertesthelper.InitDataCache: %s", err)
	}

	option.Config.HubbleLib = tus.Conf().TetragonLib
	tus.LoadSensor(t, base.GetInitialSensor())

	sensor1, err := gEnforcerPolicy.PolicyHandler(policy1, policyfilter.NoFilterID)
	assert.NoError(t, err)

	sensor2, err := policyHandler{}.PolicyHandler(policy1, policyfilter.NoFilterID)
	assert.NoError(t, err)

	sensor3, err := gEnforcerPolicy.PolicyHandler(policy2, policyfilter.NoFilterID)
	assert.NoError(t, err)

	sensor4, err := policyHandler{}.PolicyHandler(policy2, policyfilter.NoFilterID)
	assert.NoError(t, err)

	// Loading all policies
	tus.LoadSensor(t, sensor1)
	tus.LoadSensor(t, sensor2)
	tus.LoadSensor(t, sensor3)
	tus.LoadSensor(t, sensor4)

	t.Logf("All policies loaded\n")

	// 'enforcer-tester 0xffff' should be killed by policy 1
	cmd := exec.Command(testBin, "0xffff")
	err = cmd.Run()

	if err == nil || err.Error() != "signal: killed" {
		t.Fatalf("Wrong error '%v' expected 'killed'", err)
	}

	// 'enforcer-tester 0xfffe' should be killed by policy 2
	cmd = exec.Command(testBin, "0xfffe")
	err = cmd.Run()

	if err == nil || err.Error() != "signal: killed" {
		t.Fatalf("Wrong error '%v' expected 'killed'", err)
	}

	// 'enforcer-tester 0xfffd' should NOT get killed
	cmd = exec.Command(testBin, "0xfffd")
	err = cmd.Run()

	if err == nil || err.Error() != "exit status 22" {
		t.Fatalf("Wrong error '%v' expected 'exit status 22'", err)
	}

	// Unload policy 1 (watch 0xffff)
	sensor1.Unload()
	sensor2.Unload()

	t.Logf("Unloaded policy 1\n")

	// 'enforcer-tester 0xffff' should NOT get killed now
	cmd = exec.Command(testBin, "0xffff")
	err = cmd.Run()

	if err == nil || err.Error() != "exit status 22" {
		t.Fatalf("Wrong error '%v' expected 'exit status 22'", err)
	}

	// 'enforcer-tester 0xfffe' should be killed by policy 2
	cmd = exec.Command(testBin, "0xfffe")
	err = cmd.Run()

	if err == nil || err.Error() != "signal: killed" {
		t.Fatalf("Wrong error '%v' expected 'killed'", err)
	}

	// Unload policy 2 (watch 0xfffe)
	sensor3.Unload()
	sensor4.Unload()

	t.Logf("Unloaded policy 2\n")

	// 'enforcer-tester 0xfffe' should NOT get killed now
	cmd = exec.Command(testBin, "0xfffe")
	err = cmd.Run()

	if err == nil || err.Error() != "exit status 22" {
		t.Fatalf("Wrong error '%v' expected 'exit status 22'", err)
	}
}

func testEnforcerPersistent(t *testing.T, builder func() *EnforcerSpecBuilder, expected, test string) {
	testEnforcerCheckSkip(t)

	if !bpf.HasLinkPin() {
		t.Skip("skipping persistent enforcer test, link pin is not available")
	}

	run := func(idx int, exp string) {
		cmd := exec.Command(test, "0xfffe")
		err := cmd.Run()

		if err == nil || err.Error() != exp {
			t.Fatalf("run %d: Wrong error '%v' expected '%s'", idx, err, exp)
		}
	}

	yaml := builder().WithoutMultiKprobe().MustYAML()
	configHook := []byte(yaml)
	err := os.WriteFile(testConfigFile, configHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	option.Config.KeepSensorsOnExit = true
	defer func() { option.Config.KeepSensorsOnExit = false }()

	sens, err := observertesthelper.GetDefaultSensorsWithFile(t, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}

	// first run - sensors are loaded, we should get kill/override
	run(1, expected)

	sensi := make([]sensors.SensorIface, 0, len(sens))
	for _, s := range sens {
		sensi = append(sensi, s)
	}
	sensors.UnloadSensors(sensi)

	// second run - sensors are unloaded, but pins stay, we should get kill/override
	run(2, expected)

	// ... and finally get rid of pinned progs/maps/links
	os.RemoveAll(bpf.MapPrefixPath())

	// bpf pinned links removal is asynchronous, we need to wait to be sure it's gone
	time.Sleep(2 * time.Second)

	// third run - sensors are unloaded, map dir is removed, we should get no enforcement
	run(3, "exit status 22")
}

func TestEnforcerPersistentOverride(t *testing.T) {
	test := testutils.RepoRootPath("contrib/tester-progs/enforcer-tester")

	builder := func() *EnforcerSpecBuilder {
		return NewEnforcerSpecBuilder("enforcer-signal").
			WithSyscallList("sys_prctl").
			WithMatchBinaries(test).
			WithOverrideValue(-17) // EEXIST
	}

	testEnforcerPersistent(t, builder, "exit status 17", test)
}

func TestEnforcerPersistentKill(t *testing.T) {

	test := testutils.RepoRootPath("contrib/tester-progs/enforcer-tester")

	builder := func() *EnforcerSpecBuilder {
		return NewEnforcerSpecBuilder("enforcer-signal").
			WithSyscallList("sys_prctl").
			WithMatchBinaries(test).
			WithKill(9) // SigKill
	}

	testEnforcerPersistent(t, builder, "signal: killed", test)
}
