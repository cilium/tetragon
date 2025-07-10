// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/btf"
	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/grpc/tracing"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/namespace"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/cilium/tetragon/pkg/sensors/exec/execvemap"
	testsensor "github.com/cilium/tetragon/pkg/sensors/test"
	"github.com/cilium/tetragon/pkg/testutils"
	tuo "github.com/cilium/tetragon/pkg/testutils/observer"
	"github.com/cilium/tetragon/pkg/testutils/perfring"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func testMatchBinariesFollowChildren(t *testing.T, op string, result, resultMyPid int) {

	testutils.CaptureLog(t, logger.GetLogger())
	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	tmpShPath := testutils.CopyExecToTemp(t, "sh")
	event := "sys_enter_getcpu"
	spec := &v1alpha1.TracingPolicySpec{
		Tracepoints: []v1alpha1.TracepointSpec{{
			Subsystem: "syscalls",
			Event:     event,
			Args:      []v1alpha1.KProbeArg{},
			Selectors: []v1alpha1.KProbeSelector{{
				MatchBinaries: []v1alpha1.BinarySelector{{
					Operator: op,
					Values: []string{
						tmpShPath,
					},
					FollowChildren: true,
				}},
			}},
		}},
	}

	loadGenericSensorTest(t, spec)
	getcpuCnt := 0
	getcpuCntMyPid := 0
	eventFn := func(ev notify.Message) error {
		if tpEvent, ok := ev.(*tracing.MsgGenericTracepointUnix); ok {
			if tpEvent.Event != event {
				return fmt.Errorf("unexpected tracepoint event, %s:%s", tpEvent.Subsys, tpEvent.Event)
			}
			// Make sure we count only children getcpu calls
			if tpEvent.Msg.ProcessKey.Pid == namespace.GetMyPidG() {
				getcpuCntMyPid++
			} else {
				getcpuCnt++
			}
		}
		return nil
	}

	// Extra execution of getcpu syscall in current process to make sure
	// the filtering will include only proper getcpu children
	getCpu := func() {
		var cpu, node int

		_, _, err := unix.Syscall(
			unix.SYS_GETCPU,
			uintptr(unsafe.Pointer(&cpu)),
			uintptr(unsafe.Pointer(&node)),
			0,
		)
		require.Equal(t, err, syscall.Errno(0), "getcpuexec")
	}

	getcpuBin := testutils.RepoRootPath("contrib/tester-progs/getcpu")
	ops := func() {
		cmd := exec.Command(tmpShPath, "-c", getcpuBin)
		if err := cmd.Run(); err != nil {
			t.Fatalf("failed to run command %s: %v", cmd, err)
		}

		getCpu()
	}
	perfring.RunTest(t, ctx, ops, eventFn)
	require.Equal(t, result, getcpuCnt, "single exec")
	require.Equal(t, resultMyPid, getcpuCntMyPid, "single exec in current process")

	getcpuCnt = 0
	getcpuCntMyPid = 0
	ops2 := func() {
		cmd := exec.Command(tmpShPath, "-c", "exec sh -c "+getcpuBin)
		if err := cmd.Run(); err != nil {
			t.Fatalf("failed to run command %s: %v", cmd, err)
		}

		getCpu()
	}
	perfring.RunTest(t, ctx, ops2, eventFn)
	require.Equal(t, result, getcpuCnt, "double exec")
	require.Equal(t, resultMyPid, getcpuCntMyPid, "single exec in current process")
}

func TestMatchBinariesFollowChildren(t *testing.T) {
	t.Run("In", func(t *testing.T) {
		testMatchBinariesFollowChildren(t, "In", 1, 0)
	})
	t.Run("NotIn", func(t *testing.T) {
		testMatchBinariesFollowChildren(t, "NotIn", 0, 1)
	})
}

func TestMatchBinariesFollowChildrenIDs(t *testing.T) {
	// Limit this test to kprobe_multi systems, otherwise it'd take too long.
	// The mbset functionality works the same for kprobe or kprobe_multi,
	// so no harm done.

	if !bpf.HasKprobeMulti() || !config.EnableLargeProgs() {
		t.Skip("Test requires kprobe multi and large programs")
	}

	testutils.CaptureLog(t, logger.GetLogger())
	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	if err := observer.InitDataCache(1024); err != nil {
		t.Fatalf("observertesthelper.InitDataCache: %s", err)
	}

	option.Config.HubbleLib = tus.Conf().TetragonLib
	tus.LoadInitialSensor(t)
	tus.LoadSensor(t, testsensor.GetTestSensor())
	sm := tuo.GetTestSensorManager(t)

	// Create tracing policy for 64 syscalls and each of them has MatchBinaries
	// selector with FollowChildren, which uses 1 mbset ID.

	sel := []v1alpha1.KProbeSelector{
		{
			MatchBinaries: []v1alpha1.BinarySelector{
				{
					Operator:       "In",
					Values:         []string{"/usr/bin/tail"},
					FollowChildren: true,
				},
			},
		},
	}

	tp := tracingpolicy.GenericTracingPolicy{
		Metadata: v1.ObjectMeta{
			Name: "match-binaries",
		},
	}

	syscalls, err := btf.GetSyscallsList()
	require.NoError(t, err)

	for _, sc := range syscalls[:64] {
		kp := v1alpha1.KProbeSpec{
			Call:      sc,
			Syscall:   true,
			Selectors: sel,
		}
		tp.Spec.KProbes = append(tp.Spec.KProbes, kp)
	}

	// Adding the tracing policy twice (1 addition uses 64 mbset IDs) will ensure
	// that we recycle the mbset IDs properly on tracing policy removal.

	for range 2 {
		err := sm.Manager.AddTracingPolicy(ctx, &tp)
		require.NoError(t, err)
		sm.Manager.DeleteTracingPolicy(ctx, "match-binaries", "")
	}
}

func openMap(name string) (*ebpf.Map, error) {
	fname := filepath.Join(bpf.MapPrefixPath(), name)
	ret, err := ebpf.LoadPinnedMap(fname, &ebpf.LoadPinOptions{})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", fname, err)
	}
	return ret, nil
}

// This test checks on properly updated execve_map after the
// policy is added and removed. We do following:
// - add tracing policy that has MatchBinaries on "forks" binary with FollowChildren
// - executes "forks" with "count" (30000) argument that will result in count
//   fork-ed processes
// - check that all related execve_map records are updated
// - remove policy
// - check that all related execve_map records are updated

func TestMatchBinariesFollowChildrenUpdate(t *testing.T) {
	testutils.CaptureLog(t, logger.GetLogger())
	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	if !config.EnableLargeProgs() {
		t.Skip("Test requires large programs")
	}

	if err := observer.InitDataCache(1024); err != nil {
		t.Fatalf("observertesthelper.InitDataCache: %s", err)
	}

	option.Config.HubbleLib = tus.Conf().TetragonLib
	tus.LoadInitialSensor(t)
	tus.LoadSensor(t, testsensor.GetTestSensor())
	sm := tuo.GetTestSensorManager(t)

	forks := testutils.RepoRootPath("contrib/tester-progs/forks")

	tp := tracingpolicy.GenericTracingPolicy{
		Metadata: v1.ObjectMeta{
			Name: "match-binaries",
		},
		Spec: v1alpha1.TracingPolicySpec{
			KProbes: []v1alpha1.KProbeSpec{
				{
					Call:    "sys_prctl",
					Syscall: true,
					Selectors: []v1alpha1.KProbeSelector{
						{
							MatchBinaries: []v1alpha1.BinarySelector{
								{
									Operator:       "In",
									Values:         []string{forks},
									FollowChildren: true,
								},
							},
						},
					},
				},
			},
		},
	}

	// Add policy
	err := sm.Manager.AddTracingPolicy(ctx, &tp)
	require.NoError(t, err)

	count := 1000
	countStr := "1000"

	// Execute forks
	cmd := exec.Command(forks, countStr)
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to run command %s: %v", cmd, err)
	}

	// Make sure it's properly terminated
	t.Cleanup(func() {
		cmd.Process.Signal(syscall.Signal(2))
		cmd.Process.Wait()
	})

	hash, err := openMap("execve_map")
	require.NoError(t, err, "failed to open execve_map")
	defer hash.Close()

	var (
		key   execvemap.ExecveKey
		val   execvemap.ExecveValue
		found int
	)

	// Check that all "forks" processes are updated. Let's wait (maximum 2 seconds)
	// before "forks" fork-ed all the children to be sure we checked all of them.
	for range 20 {
		found = 0
		iter := hash.Iterate()
		for iter.Next(&key, &val) {
			if unix.ByteSliceToString(val.Binary.Path[:]) == forks {
				require.Equal(t, uint64(1), val.Binary.MBSet, "Binary.MBSet_1")
				found++
			}
		}
		if found == count {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	require.Equal(t, count, found, "found")

	// Remove policy
	err = sm.Manager.DeleteTracingPolicy(ctx, "match-binaries", "")
	require.NoError(t, err)

	// Check that all "forks" processes are updated
	iter := hash.Iterate()
	for iter.Next(&key, &val) {
		if unix.ByteSliceToString(val.Binary.Path[:]) == forks {
			require.Equal(t, uint64(0), val.Binary.MBSet, "Binary.MBSet_0")
		}
	}

	// "forks" is terminated via .Cleanup above
}
