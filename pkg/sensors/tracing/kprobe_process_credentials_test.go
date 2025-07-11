// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"context"
	"os"
	"strconv"
	"sync"
	"syscall"
	"testing"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	lc "github.com/cilium/tetragon/pkg/matchers/listmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/caps"
	testsensor "github.com/cilium/tetragon/pkg/sensors/test"
	"github.com/cilium/tetragon/pkg/testutils"
	tuo "github.com/cilium/tetragon/pkg/testutils/observer"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	_ "github.com/cilium/tetragon/pkg/sensors/exec"
)

func TestKprobeTraceCommitCreds(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	t.Logf("tester pid=%s\n", pidStr)

	credshook_ := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "process-creds-changed"
spec:
  kprobes:
  - call: "commit_creds"
    syscall: false
    args:
    - index: 0  # The new credentials to apply
      type: "cred"
    selectors:
    - matchPIDs:
      - operator: In
        values:
        - ` + pidStr

	testConfigFile := t.TempDir() + "/tetragon.gotest.yaml"
	writeConfigHook := []byte(credshook_)
	err := os.WriteFile(testConfigFile, writeConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	uid := 1879048192
	gid := 1879048193
	currentCaps := caps.GetCurrentCapabilities()
	myCaps := ec.NewCapabilitiesChecker().FromCapabilities(currentCaps)
	myUserns := ec.NewUserNamespaceChecker().WithUid(0).WithGid(0)
	myCredGid := ec.NewProcessCredentialsChecker().
		WithUid(uint32(0)).
		WithGid(uint32(0)).
		WithEuid(uint32(0)).
		WithEgid(uint32(gid)).
		WithSuid(uint32(0)).
		WithSgid(uint32(0)).
		WithFsuid(uint32(0)).
		WithFsgid(uint32(gid)).
		WithCaps(myCaps).
		WithUserNs(myUserns)

	kpChangeGidChecker := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full("commit_creds")).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_POST).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithValues(
				ec.NewKprobeArgumentChecker().WithProcessCredentialsArg(
					myCredGid,
				),
			),
		)

	currentECaps := &tetragon.Capabilities{
		Permitted: currentCaps.Permitted,
	}
	myECaps := ec.NewCapabilitiesChecker().FromCapabilities(currentECaps)
	myCredEUid := ec.NewProcessCredentialsChecker().
		WithUid(uint32(0)).
		WithGid(uint32(0)).
		WithEuid(uint32(uid)).
		WithEgid(uint32(gid)).
		WithSuid(uint32(0)).
		WithSgid(uint32(0)).
		WithFsuid(uint32(uid)).
		WithFsgid(uint32(gid)).
		WithCaps(myECaps).
		WithUserNs(myUserns)

	kpChangeUidChecker := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full("commit_creds")).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_POST).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithValues(
				ec.NewKprobeArgumentChecker().WithProcessCredentialsArg(
					myCredEUid,
				),
			),
		)

	myPrivilegedCred := ec.NewProcessCredentialsChecker().
		WithUid(uint32(0)).
		WithGid(uint32(gid + 1)).
		WithEuid(uint32(0)).
		WithEgid(uint32(gid + 1)).
		WithSuid(uint32(0)).
		WithSgid(uint32(gid + 1)).
		WithFsuid(uint32(0)).
		WithFsgid(uint32(gid + 1)).
		WithCaps(myCaps).
		WithUserNs(myUserns)

	kpPrivilegedChecker := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full("commit_creds")).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_POST).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithValues(
				ec.NewKprobeArgumentChecker().WithProcessCredentialsArg(
					myPrivilegedCred,
				),
			),
		)

	// Drop effective gid
	if err := syscall.Setegid(gid); err != nil {
		t.Fatalf("setegid(%d) error: %s", gid, err)
	}

	t.Logf("setegid(%d) succeeded", gid)

	// Drop effective uid only
	if err := syscall.Seteuid(uid); err != nil {
		t.Fatalf("seteuid(%d) error: %s", uid, err)
	}

	t.Logf("seteuid(%d) succeeded", uid)

	// Restore all uids to 0 , also all caps and allow to clean up tests
	if err := syscall.Setuid(0); err != nil {
		t.Fatalf("setuid(0) error: %s", err)
	}

	// Reset all gids to gid+1 so we match the event
	if err := syscall.Setgid(gid + 1); err != nil {
		t.Fatalf("setgid(%d) error: %s", gid+1, err)
	}

	checker := ec.NewUnorderedEventChecker(kpChangeGidChecker, kpChangeUidChecker, kpPrivilegedChecker)
	err = jsonchecker.JsonTestCheck(t, checker)
	require.NoError(t, err)
}

func TestKprobeTraceSecureBits(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))
	t.Logf("tester pid=%s\n", pidStr)

	credshook_ := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "process-creds-changed"
spec:
  kprobes:
  - call: "commit_creds"
    syscall: false
    args:
    - index: 0  # The new credentials to apply
      type: "cred"
    selectors:
    - matchPIDs:
      - operator: In
        values:
        - ` + pidStr

	testConfigFile := t.TempDir() + "/tetragon.gotest.yaml"
	writeConfigHook := []byte(credshook_)
	err := os.WriteFile(testConfigFile, writeConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	uid := 1879048192
	gid := 1879048193
	currentCaps := caps.GetCurrentCapabilities()
	myCaps := ec.NewCapabilitiesChecker().FromCapabilities(currentCaps)
	myUserns := ec.NewUserNamespaceChecker().WithUid(0).WithGid(0)
	myCredGid := ec.NewProcessCredentialsChecker().
		WithUid(uint32(0)).
		WithGid(uint32(gid)).
		WithEuid(uint32(0)).
		WithEgid(uint32(gid)).
		WithSuid(uint32(0)).
		WithSgid(uint32(gid)).
		WithFsuid(uint32(0)).
		WithFsgid(uint32(gid)).
		WithCaps(myCaps).
		WithUserNs(myUserns)

	kpChangeGidChecker := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full("commit_creds")).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_POST).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithValues(
				ec.NewKprobeArgumentChecker().WithProcessCredentialsArg(
					myCredGid,
				),
			),
		)

	currentECaps := &tetragon.Capabilities{
		Permitted: currentCaps.Permitted,
	}
	myECaps := ec.NewCapabilitiesChecker().FromCapabilities(currentECaps)
	myBits := ec.NewSecureBitsTypeListMatcher().WithOperator(lc.Ordered).
		WithValues(
			ec.NewSecureBitsTypeChecker(tetragon.SecureBitsType_SecBitKeepCaps),
			ec.NewSecureBitsTypeChecker(tetragon.SecureBitsType_SecBitNoCapAmbientRaise))
	myCredEUid := ec.NewProcessCredentialsChecker().
		WithUid(uint32(0)).
		WithGid(uint32(gid)).
		WithEuid(uint32(uid)).
		WithEgid(uint32(gid)).
		WithSuid(uint32(0)).
		WithSgid(uint32(gid)).
		WithFsuid(uint32(uid)).
		WithFsgid(uint32(gid)).
		WithSecurebits(myBits).
		WithCaps(myECaps).
		WithUserNs(myUserns)

	kpChangeUidChecker := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full("commit_creds")).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_POST).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithValues(
				ec.NewKprobeArgumentChecker().WithProcessCredentialsArg(
					myCredEUid,
				),
			),
		)

	myPrivilegedCred := ec.NewProcessCredentialsChecker().
		WithUid(uint32(0)).
		WithGid(uint32(gid + 1)).
		WithEuid(uint32(0)).
		WithEgid(uint32(gid + 1)).
		WithSuid(uint32(0)).
		WithSgid(uint32(gid + 1)).
		WithFsuid(uint32(0)).
		WithFsgid(uint32(gid + 1)).
		WithSecurebits(myBits).
		WithCaps(myCaps).
		WithUserNs(myUserns)

	kpPrivilegedChecker := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full("commit_creds")).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_POST).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithValues(
				ec.NewKprobeArgumentChecker().WithProcessCredentialsArg(
					myPrivilegedCred,
				),
			),
		)

	// Drop all gid
	if err := syscall.Setgid(gid); err != nil {
		t.Fatalf("setgid(%d) error: %s", gid, err)
	}

	t.Logf("setgid(%d) succeeded", gid)

	if err := unix.Prctl(unix.PR_SET_SECUREBITS,
		uintptr(tetragon.SecureBitsType_SecBitKeepCaps|tetragon.SecureBitsType_SecBitNoCapAmbientRaise), 0, 0, 0); err != nil {
		t.Fatalf("prctl() set secrurebits error: %s", err)
	}

	t.Log("prctl() securebits succeeded")

	// Drop effective uid only
	if err := syscall.Seteuid(uid); err != nil {
		t.Fatalf("seteuid(%d) error: %s", uid, err)
	}

	t.Logf("seteuid(%d) succeeded", uid)

	// Restore all uids to 0 , also all caps and allow to clean up tests
	if err := syscall.Setuid(0); err != nil {
		t.Fatalf("setuid(0) error: %s", err)
	}

	// Reset all gids to gid+1 so we match the event
	if err := syscall.Setgid(gid + 1); err != nil {
		t.Fatalf("setgid(%d) error: %s", gid+1, err)
	}

	checker := ec.NewUnorderedEventChecker(kpChangeGidChecker, kpChangeUidChecker, kpPrivilegedChecker)
	err = jsonchecker.JsonTestCheck(t, checker)
	require.NoError(t, err)
}

func TestKprobeMatchCurrentCredValidity(t *testing.T) {
	testutils.CaptureLog(t, logger.GetLogger())
	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	option.Config.HubbleLib = tus.Conf().TetragonLib
	tus.LoadInitialSensor(t)
	tus.LoadSensor(t, testsensor.GetTestSensor())
	sm := tuo.GetTestSensorManager(t)

	typeMeta := v1.TypeMeta{
		APIVersion: "cilium.io/v1alpha1",
		Kind:       "TracingPolicy",
	}
	Spec := v1alpha1.TracingPolicySpec{
		KProbes: []v1alpha1.KProbeSpec{{
			Call:    "commit_creds",
			Syscall: false,
		}},
	}

	tests := map[string]struct {
		cred []v1alpha1.CredentialsSelector
		err  bool
	}{
		"cred1": {
			cred: []v1alpha1.CredentialsSelector{
				{
					UIDs: []v1alpha1.CredIDValues{
						{
							Operator: "Equal",
							Values:   []string{"0:0"},
						},
					},
					EUIDs: []v1alpha1.CredIDValues{
						{
							Operator: "Equal",
							Values:   []string{"0:0"},
						},
					},
				},
				{
					UIDs: []v1alpha1.CredIDValues{
						{
							Operator: "Equal",
							Values:   []string{"0:0"},
						},
					},
				},
			},
			err: true,
		},
		"cred2": {
			cred: []v1alpha1.CredentialsSelector{
				{
					UIDs: []v1alpha1.CredIDValues{
						{
							Operator: "Equal",
							Values:   []string{"0:0"},
						},
					},
					EUIDs: []v1alpha1.CredIDValues{
						{
							Operator: "Equal",
							Values:   []string{"0:0"},
						},
					},
				},
				{
					EUIDs: []v1alpha1.CredIDValues{
						{
							Operator: "Equal",
							Values:   []string{"0:0"},
						},
					},
				},
			},
			err: true,
		},
		"cred3": {
			cred: []v1alpha1.CredentialsSelector{
				{
					UIDs: []v1alpha1.CredIDValues{
						{
							Operator: "NotEqual",
							Values:   []string{"-1:4294967296"},
						},
					},
				},
			},
			err: true,
		},
		"cred4": {
			cred: []v1alpha1.CredentialsSelector{
				{
					UIDs: []v1alpha1.CredIDValues{
						{
							Operator: "Equal",
							Values:   []string{"0:0"},
						},
					},
				},
				{
					EUIDs: []v1alpha1.CredIDValues{
						{
							Operator: "Equal",
							Values:   []string{"0:0"},
						},
					},
				},
			},
			err: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			Spec.KProbes[0].Selectors = []v1alpha1.KProbeSelector{
				{
					MatchCurrentCred: test.cred,
				},
			}
			policy := tracingpolicy.GenericTracingPolicy{
				TypeMeta: typeMeta,
				Metadata: v1.ObjectMeta{Name: name},
				Spec: v1alpha1.TracingPolicySpec{
					KProbes: Spec.KProbes,
				},
			}
			err := sm.Manager.AddTracingPolicy(ctx, &policy)
			if test.err {
				require.Error(t, err)
			} else {
				/* Even we do not require an error, matchCurrentCred will
				 * always fail on old kernels.
				 */
				if !config.EnableLargeProgs() {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
				}
			}
			if err == nil {
				sm.Manager.DeleteTracingPolicy(ctx, name, "")
			}
		})
	}
}
