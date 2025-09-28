// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	lc "github.com/cilium/tetragon/pkg/matchers/listmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/reader/caps"
	"github.com/cilium/tetragon/pkg/testutils"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"

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

	// Restore all gids to 0
	if err := syscall.Setgid(0); err != nil {
		t.Fatalf("setgid(0) error: %s", err)
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

	// Restore all gids to 0
	if err := syscall.Setgid(0); err != nil {
		t.Fatalf("setgid(0) error: %s", err)
	}

	checker := ec.NewUnorderedEventChecker(kpChangeGidChecker, kpChangeUidChecker, kpPrivilegedChecker)
	err = jsonchecker.JsonTestCheck(t, checker)
	require.NoError(t, err)
}

/*  TestKprobeMatchCurrentCredRealUid() matches against current real uid.
 *
 *  ** Important **
 *
 *  1. Tests starts with root uid 0
 *
 *  2. Tests executes drop-privileges, in Tetragon userspace cached process credentials
 *     are ruid/euid == 0
 *
 *  3. drop-privileges changes its reuid to 1879048188
 *     but cached state is still uid/euid == 0 since execve snapshot.
 *
 *     But in kernel, current credentials are uid/euid == 1879048188. These
 *     are the ones that we use for matching.
 *
 *  4. drop-privileges executes /usr/bin/echo
 *     In tetragon userpace uid == 0, but in kernel current uid == 1879048188
 *
 *     In tracing policy we match against current credentials 1879048188
 *     In Process json output checker we match against cached shadow state
 *     credentials uid/euid == 0.
 *
 *  5. /usr/bin/echo starts with uid/euid == 1879048188
 *     In tetragon uid == 1879048188 same in kernel current uid == 1879048188
 */
func TestKprobeMatchCurrentCredRealUid(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	if !config.EnableLargeProgs() {
		t.Skipf("Skipping test since it needs kernel >= 5.3")
	}

	// The drop-privileges is a helper binary that drops privileges so we do not
	// drop it inside this test which will break the test framework.
	testDrop := testutils.RepoRootPath("contrib/tester-progs/drop-privileges")
	testEcho, err := exec.LookPath("echo")
	if err != nil {
		t.Skipf("Skipping test could not find 'echo' binary: %v", err)
	}

	credshook_ := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "process-creds-changed"
spec:
  kprobes:
  - call: "security_bprm_committed_creds"
    syscall: false
    args:
    - index: 0
      resolve: file
      type: "file"
    data:
    - type: "int"
      source: "current_task"
      resolve: "cred.uid.val"
    selectors:
    - matchBinaries:
      - operator: "In"
        values:
        - "` + testDrop + `"
      matchArgs:
      - index: 0
        operator: "Postfix"
        values:
        - "` + testEcho + `"
      matchData:
      - index: 0
        operator: InRange
        values:
        - "1879048180:1879048189"
`

	testConfigFile := t.TempDir() + "/tetragon.gotest.yaml"
	writeConfigHook := []byte(credshook_)
	err = os.WriteFile(testConfigFile, writeConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}

	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	cachedTetragonCreds := ec.NewProcessCredentialsChecker().
		WithUid(0).
		WithGid(0).
		WithEuid(0).
		WithEgid(0).
		WithSuid(0).
		WithSgid(0).
		WithFsuid(0).
		WithFsgid(0)

	processChecker := ec.NewProcessChecker().
		WithUid(0).
		WithBinary(sm.Full(testDrop)).
		WithProcessCredentials(cachedTetragonCreds)

	kpCurrentUid := ec.NewProcessKprobeChecker("").
		WithProcess(processChecker).
		WithFunctionName(sm.Full("security_bprm_committed_creds")).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_POST)

	testCmd := exec.CommandContext(ctx, testDrop, testEcho, "hello")
	if err := testCmd.Start(); err != nil {
		t.Fatal(err)
	}

	if err := testCmd.Wait(); err != nil {
		t.Fatalf("command failed with %s. Context error: %v", err, ctx.Err())
	}

	if err := syscall.Setuid(0); err != nil {
		t.Fatalf("setuid(0) error: %s", err)
	}
	if err := syscall.Setgid(0); err != nil {
		t.Fatalf("setgid(0) error: %s", err)
	}

	checker := ec.NewUnorderedEventChecker(kpCurrentUid)
	err = jsonchecker.JsonTestCheck(t, checker)
	require.NoError(t, err)
}

func TestKprobeMatchCurrentCredRealUidNotEqual(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	if !config.EnableLargeProgs() {
		t.Skipf("Skipping test since it needs kernel >= 5.3")
	}

	// The drop-privileges is a helper binary that drops privileges so we do not
	// drop it inside this test which will break the test framework.
	testDrop := testutils.RepoRootPath("contrib/tester-progs/drop-privileges")
	testEcho, err := exec.LookPath("echo")
	if err != nil {
		t.Skipf("Skipping test could not find 'echo' binary: %v", err)
	}

	credshook_ := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "process-creds-changed"
spec:
  kprobes:
  - call: "security_bprm_committed_creds"
    syscall: false
    args:
    - index: 0
      resolve: file
      type: "file"
    data:
    - type: "int"
      source: "current_task"
      resolve: "cred.uid.val"
    selectors:
    - matchBinaries:
      - operator: "In"
        values:
        - "` + testDrop + `"
      matchArgs:
      - index: 0
        operator: "Postfix"
        values:
        - "` + testEcho + `"
      matchData:
      - index: 0
        operator: NotInRange
        values:
        - "0:187904818"
        - "187904818:1879048187"
        - "1879048189:4294967295"
`

	testConfigFile := t.TempDir() + "/tetragon.gotest.yaml"
	writeConfigHook := []byte(credshook_)
	err = os.WriteFile(testConfigFile, writeConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}

	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	cachedTetragonCreds := ec.NewProcessCredentialsChecker().
		WithUid(0).
		WithGid(0).
		WithEuid(0).
		WithEgid(0).
		WithSuid(0).
		WithSgid(0).
		WithFsuid(0).
		WithFsgid(0)

	processChecker := ec.NewProcessChecker().
		WithUid(0).
		WithBinary(sm.Full(testDrop)).
		WithProcessCredentials(cachedTetragonCreds)

	kpCurrentUid := ec.NewProcessKprobeChecker("").
		WithProcess(processChecker).
		WithFunctionName(sm.Full("security_bprm_committed_creds")).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_POST)

	testCmd := exec.CommandContext(ctx, testDrop, testEcho, "hello")
	if err := testCmd.Start(); err != nil {
		t.Fatal(err)
	}
	if err := testCmd.Wait(); err != nil {
		t.Fatalf("command failed with %s. Context error: %v", err, ctx.Err())
	}

	if err := syscall.Setuid(0); err != nil {
		t.Fatalf("setuid(0) error: %s", err)
	}
	if err := syscall.Setgid(0); err != nil {
		t.Fatalf("setgid(0) error: %s", err)
	}

	checker := ec.NewUnorderedEventChecker(kpCurrentUid)
	err = jsonchecker.JsonTestCheck(t, checker)
	require.NoError(t, err)
}

func TestKprobeMatchCurrentCredRealEffectiveUid(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	if !config.EnableLargeProgs() {
		t.Skipf("Skipping test since it needs kernel >= 5.3")
	}

	// The drop-privileges is a helper binary that drops privileges so we do not
	// drop it inside this test which will break the test framework.
	testDrop := testutils.RepoRootPath("contrib/tester-progs/drop-privileges")
	testEcho, err := exec.LookPath("echo")
	if err != nil {
		t.Skipf("Skipping test could not find 'echo' binary: %v", err)
	}

	credshook_ := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "process-creds-changed"
spec:
  kprobes:
  - call: "security_bprm_committed_creds"
    syscall: false
    args:
    - index: 0
      resolve: file
      type: "file"
    data:
    - type: "int"
      source: "current_task"
      resolve: "cred.uid.val"
    - type: "int"
      source: "current_task"
      resolve: "cred.euid.val"
    selectors:
    - matchBinaries:
      - operator: "In"
        values:
        - "` + testDrop + `"
      matchArgs:
      - index: 0
        operator: "Postfix"
        values:
        - "` + testEcho + `"
      matchData:
      - index: 0
        operator: InRange
        values:
        - "1879048180:1879048188"
      - index: 1
        operator: InRange
        values:
        - "1879048180:1879048188"
`

	testConfigFile := t.TempDir() + "/tetragon.gotest.yaml"
	writeConfigHook := []byte(credshook_)
	err = os.WriteFile(testConfigFile, writeConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}

	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	cachedTetragonCreds := ec.NewProcessCredentialsChecker().
		WithUid(0).
		WithGid(0).
		WithEuid(0).
		WithEgid(0).
		WithSuid(0).
		WithSgid(0).
		WithFsuid(0).
		WithFsgid(0)

	processChecker := ec.NewProcessChecker().
		WithUid(0).
		WithBinary(sm.Full(testDrop)).
		WithProcessCredentials(cachedTetragonCreds)

	kpCurrentUid := ec.NewProcessKprobeChecker("").
		WithProcess(processChecker).
		WithFunctionName(sm.Full("security_bprm_committed_creds")).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_POST)

	testCmd := exec.CommandContext(ctx, testDrop, testEcho, "hello")
	if err := testCmd.Start(); err != nil {
		t.Fatal(err)
	}
	if err := testCmd.Wait(); err != nil {
		t.Fatalf("command failed with %s. Context error: %v", err, ctx.Err())
	}

	if err := syscall.Setuid(0); err != nil {
		t.Fatalf("setuid(0) error: %s", err)
	}
	if err := syscall.Setgid(0); err != nil {
		t.Fatalf("setgid(0) error: %s", err)
	}

	checker := ec.NewUnorderedEventChecker(kpCurrentUid)
	err = jsonchecker.JsonTestCheck(t, checker)
	require.NoError(t, err)
}

func TestKprobeMatchCurrentCredRealEffectiveUidNotEqual(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	if !config.EnableLargeProgs() {
		t.Skipf("Skipping test since it needs kernel >= 5.3")
	}

	// The drop-privileges is a helper binary that drops privileges so we do not
	// drop it inside this test which will break the test framework.
	testDrop := testutils.RepoRootPath("contrib/tester-progs/drop-privileges")
	testEcho, err := exec.LookPath("echo")
	if err != nil {
		t.Skipf("Skipping test could not find 'echo' binary: %v", err)
	}

	credshook_ := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "process-creds-changed"
spec:
  kprobes:
  - call: "security_bprm_committed_creds"
    syscall: false
    args:
    - index: 0
      resolve: file
      type: "file"
    data:
    - type: "int"
      source: "current_task"
      resolve: "cred.uid.val"
    - type: "int"
      source: "current_task"
      resolve: "cred.euid.val"
    selectors:
    - matchBinaries:
      - operator: "In"
        values:
        - "` + testDrop + `"
      matchArgs:
      - index: 0
        operator: "Postfix"
        values:
        - "` + testEcho + `"
      matchData:
      - index: 0
        operator: NotInRange
        values:
        - "0:187904818"
        - "1879048189:4294967295"
      - index: 1
        operator: NotInRange
        values:
        - "0:187904818"
        - "1879048186:1879048187"
        - "1879048189:4294967295"
`

	testConfigFile := t.TempDir() + "/tetragon.gotest.yaml"
	writeConfigHook := []byte(credshook_)
	err = os.WriteFile(testConfigFile, writeConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}

	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	cachedTetragonCreds := ec.NewProcessCredentialsChecker().
		WithUid(0).
		WithGid(0).
		WithEuid(0).
		WithEgid(0).
		WithSuid(0).
		WithSgid(0).
		WithFsuid(0).
		WithFsgid(0)

	processChecker := ec.NewProcessChecker().
		WithUid(0).
		WithBinary(sm.Full(testDrop)).
		WithProcessCredentials(cachedTetragonCreds)

	kpCurrentUid := ec.NewProcessKprobeChecker("").
		WithProcess(processChecker).
		WithFunctionName(sm.Full("security_bprm_committed_creds")).
		WithAction(tetragon.KprobeAction_KPROBE_ACTION_POST)

	testCmd := exec.CommandContext(ctx, testDrop, testEcho, "hello")
	if err := testCmd.Start(); err != nil {
		t.Fatal(err)
	}
	if err := testCmd.Wait(); err != nil {
		t.Fatalf("command failed with %s. Context error: %v", err, ctx.Err())
	}

	if err := syscall.Setuid(0); err != nil {
		t.Fatalf("setuid(0) error: %s", err)
	}
	if err := syscall.Setgid(0); err != nil {
		t.Fatalf("setgid(0) error: %s", err)
	}

	checker := ec.NewUnorderedEventChecker(kpCurrentUid)
	err = jsonchecker.JsonTestCheck(t, checker)
	require.NoError(t, err)
}
