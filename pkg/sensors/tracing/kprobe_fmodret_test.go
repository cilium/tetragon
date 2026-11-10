// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/idtable"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/policyconf"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

func sharedFmodretSpec(file string, errno unix.Errno) *v1alpha1.TracingPolicySpec {
	return &v1alpha1.TracingPolicySpec{
		KProbes: []v1alpha1.KProbeSpec{
			{
				Call: "security_file_open",
				Args: []v1alpha1.KProbeArg{
					{
						Index: 0,
						Type:  "file",
					},
				},
				Selectors: []v1alpha1.KProbeSelector{
					{
						MatchArgs: []v1alpha1.ArgSelector{
							{
								Index:    0,
								Operator: "Equal",
								Values:   []string{file},
							},
						},
						MatchActions: []v1alpha1.ActionSelector{
							{
								Action:   "Override",
								ArgError: -int32(errno),
							},
						},
					},
				},
			},
		},
	}
}

func requireOpenError(t *testing.T, file string, want error) {
	t.Helper()

	fd, err := unix.Open(file, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if fd >= 0 {
		require.NoError(t, unix.Close(fd))
	}

	if want == nil {
		require.NoError(t, err)
	} else {
		require.ErrorIs(t, err, want)
	}
}

func TestSharedFmodretPolicies(t *testing.T) {
	if !bpf.HasModifyReturn() || !bpf.HasKprobeMulti() || option.Config.DisableKprobeMulti {
		t.Skip("requires fmod_ret and kprobe.multi")
	}

	files := []string{
		filepath.Join(t.TempDir(), "first"),
		filepath.Join(t.TempDir(), "second"),
		filepath.Join(t.TempDir(), "allowed"),
	}
	for _, file := range files {
		require.NoError(t, os.WriteFile(file, nil, 0600))
	}

	first, firstInfo := loadSharedKprobePolicy(
		t,
		"shared-fmodret-first",
		sharedFmodretSpec(files[0], unix.ENOENT),
	)

	second, _ := loadSharedKprobePolicy(
		t,
		"shared-fmodret-second",
		sharedFmodretSpec(files[1], unix.EACCES),
	)

	shared := sharedMultiKprobes[0]
	target := shared.fmodret.byFunction["security_file_open"]
	require.NotNil(t, target)
	require.Equal(
		t,
		multiKprobePinName("fmodret", "security_file_open", target.target),
		filepath.Base(target.dir),
	)
	require.Equal(t, 2, target.refs)
	require.Empty(t, first.Progs[0].AttachData.(*program.MultiKprobeAttachData).Overrides)

	_, err := os.Stat(filepath.Join(target.dir, "prog_cleanup"))
	require.NoError(t, err)
	if bpf.HasLinkPin() {
		for _, name := range []string{"link", "link_cleanup"} {
			_, err := os.Stat(filepath.Join(target.dir, name))
			require.NoError(t, err)
		}
	}

	requireOpenError(t, files[0], unix.ENOENT)
	requireOpenError(t, files[1], unix.EACCES)
	requireOpenError(t, files[2], nil)

	require.NoError(t, firstInfo.policyConf.MapHandle.Update(
		uint32(0),
		&policyconf.PolicyConf{
			Mode: policyconf.MonitorMode,
		},
		ebpf.UpdateAny,
	))

	requireOpenError(t, files[0], nil)
	requireOpenError(t, files[1], unix.EACCES)

	cookie := first.Progs[0].AttachData.(*program.MultiKprobeAttachData).Cookies[0]
	scope := uint32(cookie >> 32)
	var oldBinding fmodretBinding
	require.NoError(t, shared.maps["fmodret_targets"].MapHandle.Lookup(scope, &oldBinding))

	require.NoError(t, first.Unload(true))
	require.Equal(t, 1, target.refs)

	var binding fmodretBinding
	require.ErrorIs(t, shared.maps["fmodret_targets"].MapHandle.Lookup(scope, &binding), ebpf.ErrKeyNotExist)

	requireOpenError(t, files[0], nil)
	requireOpenError(t, files[1], unix.EACCES)

	// A revoked action must not apply to a reloaded policy, even when its
	// scope number is recycled. Pin the thread so the handoff uses this TID.
	require.NoError(t, first.Load(bpf.MapPrefixPath()))
	require.Same(t, target, shared.fmodret.byFunction["security_file_open"])
	require.Equal(t, 2, target.refs)

	cookie = first.Progs[0].AttachData.(*program.MultiKprobeAttachData).Cookies[0]
	require.Equal(t, scope, uint32(cookie>>32))
	require.NoError(t, shared.maps["fmodret_targets"].MapHandle.Lookup(scope, &binding))
	require.NotEqual(t, oldBinding.Generation, binding.Generation)

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	key := fmodretKey{
		PIDTgid: uint64(os.Getpid())<<32 | uint64(unix.Gettid()),
		Target:  target.target,
	}

	stale := fmodretAction{
		Scope:      scope,
		Error:      -int32(unix.EPERM),
		Generation: oldBinding.Generation,
	}
	require.NoError(t, shared.maps["fmodret_tasks"].MapHandle.Update(key, stale, ebpf.UpdateAny))
	requireOpenError(t, files[2], nil)
	require.ErrorIs(t, shared.maps["fmodret_tasks"].MapHandle.Lookup(key, &stale), ebpf.ErrKeyNotExist)
	requireOpenError(t, files[0], unix.ENOENT)
	requireOpenError(t, files[1], unix.EACCES)

	require.NoError(t, first.Unload(true))

	// Last-reference cleanup also removes handoffs whose functions never ran.
	key.PIDTgid = 0
	require.NoError(t, shared.maps["fmodret_tasks"].MapHandle.Update(key, stale, ebpf.UpdateAny))
	require.NoError(t, second.Unload(true))
	require.NotContains(t, shared.fmodret.byFunction, "security_file_open")

	_, err = os.Stat(target.dir)
	require.ErrorIs(t, err, os.ErrNotExist)
	require.ErrorIs(t, shared.maps["fmodret_tasks"].MapHandle.Lookup(key, &stale), ebpf.ErrKeyNotExist)
	requireOpenError(t, files[1], nil)
}

func TestSharedFmodretZeroOverride(t *testing.T) {
	if !bpf.HasModifyReturn() || !bpf.HasKprobeMulti() || option.Config.DisableKprobeMulti {
		t.Skip("requires fmod_ret and kprobe.multi")
	}

	for _, zeroFirst := range []bool{true, false} {
		t.Run(fmt.Sprintf("zero-first-%t", zeroFirst), func(t *testing.T) {
			dir := t.TempDir()
			denied := filepath.Join(dir, "denied")
			zeroOnly := filepath.Join(dir, "zero-only")
			for _, file := range []string{denied, zeroOnly} {
				require.NoError(t, os.WriteFile(file, nil, 0600))
			}

			zeroSpec := sharedFmodretSpec(denied, 0)
			zeroSpec.KProbes[0].Selectors[0].MatchArgs[0].Values = []string{denied, zeroOnly}

			loadZero := func() {
				loadSharedKprobePolicy(t, "shared-fmodret-zero", zeroSpec)
			}
			if zeroFirst {
				loadZero()
			}

			deny, _ := loadSharedKprobePolicy(
				t,
				"shared-fmodret-deny",
				sharedFmodretSpec(denied, unix.EACCES),
			)

			if !zeroFirst {
				loadZero()
			}

			requireOpenError(t, denied, unix.EACCES)
			requireOpenError(t, zeroOnly, nil)

			// Seed a denial to represent a policy that already matched in
			// this invocation. Only the zero policy matches the next open,
			// so this also tests the overwrite case independently of link order.
			shared := sharedMultiKprobes[0]
			cookie := deny.Progs[0].AttachData.(*program.MultiKprobeAttachData).Cookies[0]
			scope := uint32(cookie >> 32)

			var binding fmodretBinding
			require.NoError(t, shared.maps["fmodret_targets"].MapHandle.Lookup(scope, &binding))

			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			key := fmodretKey{
				PIDTgid: uint64(os.Getpid())<<32 | uint64(unix.Gettid()),
				Target:  binding.Target,
			}

			action := fmodretAction{
				Scope:      scope,
				Error:      -int32(unix.EACCES),
				Generation: binding.Generation,
			}

			require.NoError(t, shared.maps["fmodret_tasks"].MapHandle.Update(key, action, ebpf.UpdateAny))
			requireOpenError(t, zeroOnly, unix.EACCES)
			require.ErrorIs(t, shared.maps["fmodret_tasks"].MapHandle.Lookup(key, &action), ebpf.ErrKeyNotExist)
			requireOpenError(t, zeroOnly, nil)
		})
	}
}

func TestSharedFmodretSkippedHandlerCleanup(t *testing.T) {
	if !bpf.HasModifyReturn() || !bpf.HasKprobeMulti() || option.Config.DisableKprobeMulti {
		t.Skip("requires fmod_ret and kprobe.multi")
	}

	dir := t.TempDir()
	denied := filepath.Join(dir, "denied")
	allowed := filepath.Join(dir, "allowed")
	for _, file := range []string{denied, allowed} {
		require.NoError(t, os.WriteFile(file, nil, 0600))
	}

	loadSharedKprobePolicy(t, "shared-fmodret-skipped", sharedFmodretSpec(denied, unix.ENOENT))

	shared := sharedMultiKprobes[0]
	target := shared.fmodret.byFunction["security_file_open"]

	// Trampoline handlers run newest first. A later non-multi policy denies
	// before the shared handler, but the shared fexit cleanup must still run.
	classicSpec := sharedFmodretSpec(denied, unix.EACCES)
	classicSpec.Options = []v1alpha1.OptionSpec{
		{
			Name:  option.KeyDisableKprobeMulti,
			Value: "true",
		},
	}
	classic, _ := loadSharedKprobePolicy(t, "classic-fmodret-first", classicSpec)
	require.True(t, classic.Progs[0].OverrideFmodRet)
	require.False(t, classic.Progs[0].SharedStats)

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	key := fmodretKey{
		PIDTgid: uint64(os.Getpid())<<32 | uint64(unix.Gettid()),
		Target:  target.target,
	}

	var action fmodretAction
	for range 3 {
		requireOpenError(t, denied, unix.EACCES)
		require.ErrorIs(t, shared.maps["fmodret_tasks"].MapHandle.Lookup(key, &action), ebpf.ErrKeyNotExist)
		requireOpenError(t, allowed, nil)
	}
}

func TestSharedFmodretLoadRollback(t *testing.T) {
	if !bpf.HasModifyReturn() || !bpf.HasKprobeMulti() || option.Config.DisableKprobeMulti {
		t.Skip("requires fmod_ret and kprobe.multi")
	}

	file := filepath.Join(t.TempDir(), "denied")
	require.NoError(t, os.WriteFile(file, nil, 0600))

	first, _ := loadSharedKprobePolicy(
		t,
		"shared-fmodret-existing",
		sharedFmodretSpec(file, unix.EACCES),
	)

	shared := sharedMultiKprobes[0]
	target := shared.fmodret.byFunction["security_file_open"]

	spec := sharedFmodretSpec(file, unix.ENOENT)
	// Create a valid sensor, then force the multi-link attachment to fail
	// after it has acquired a reference to the existing fmod_ret program.
	spec.KProbes = append(spec.KProbes, v1alpha1.KProbeSpec{
		Call: "security_file_permission",
	})
	pi, err := newPolicyInfoFromSpec("", "", "shared-fmodret-failed", policyfilter.NoFilterID, spec, nil)
	require.NoError(t, err)
	failed, err := createGenericKprobeSensor(spec, "generic_kprobe", pi, simpleValidateInfo(spec.KProbes), kprobe)
	require.NoError(t, err)
	t.Cleanup(func() {
		failed.Destroy(true)
	})

	ids := failed.Progs[0].LoaderData.([]idtable.EntryID)
	hook, err := genericKprobeTableGet(ids[1])
	require.NoError(t, err)

	hook.funcName = "__tetragon_nonexistent_fmodret_test"
	require.Error(t, failed.Load(bpf.MapPrefixPath()))
	require.Equal(t, 1, target.refs)
	require.Same(t, target, shared.fmodret.byFunction["security_file_open"])
	requireOpenError(t, file, unix.EACCES)
	require.NoError(t, first.Unload(true))
	require.NotContains(t, shared.fmodret.byFunction, "security_file_open")
}

func TestSharedFmodretHooks(t *testing.T) {
	if !bpf.HasModifyReturn() || !bpf.HasKprobeMulti() || option.Config.DisableKprobeMulti {
		t.Skip("requires fmod_ret and kprobe.multi")
	}

	openFile := filepath.Join(t.TempDir(), "deny-open")
	readFile := filepath.Join(t.TempDir(), "deny-read")
	for _, file := range []string{openFile, readFile} {
		require.NoError(t, os.WriteFile(file, []byte("test"), 0600))
	}

	fd, err := unix.Open(readFile, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	require.NoError(t, err)
	defer unix.Close(fd)

	spec := sharedFmodretSpec(openFile, unix.ENOENT)
	permission := sharedFmodretSpec(readFile, unix.EACCES).KProbes[0]
	permission.Call = "security_file_permission"
	permission.Return = true
	permission.ReturnArg = &v1alpha1.KProbeArg{
		Index: 0,
		Type:  "int",
	}

	spec.KProbes = append(spec.KProbes, permission)
	sensor, _ := loadSharedKprobePolicy(t, "shared-fmodret-hooks", spec)

	shared := sharedMultiKprobes[0]
	openTarget := shared.fmodret.byFunction["security_file_open"]
	readTarget := shared.fmodret.byFunction["security_file_permission"]
	require.NotNil(t, openTarget)
	require.NotNil(t, readTarget)
	require.NotEqual(t, openTarget.target, readTarget.target)

	requireOpenError(t, openFile, unix.ENOENT)
	requireOpenError(t, readFile, nil)
	_, err = unix.Read(fd, make([]byte, 4))
	require.ErrorIs(t, err, unix.EACCES)
	require.NoError(t, sensor.Unload(true))

	_, err = unix.Read(fd, make([]byte, 4))
	require.NoError(t, err)
}
