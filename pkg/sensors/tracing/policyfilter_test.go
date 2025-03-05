// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cilium/tetragon/pkg/api/tracingapi"
	"github.com/cilium/tetragon/pkg/bpf"
	tgcgroups "github.com/cilium/tetragon/pkg/cgroups"
	grpcexec "github.com/cilium/tetragon/pkg/grpc/exec"
	"github.com/cilium/tetragon/pkg/grpc/tracing"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/cilium/tetragon/pkg/sensors/config/confmap"
	testsensor "github.com/cilium/tetragon/pkg/sensors/test"
	"github.com/cilium/tetragon/pkg/testutils"
	tuo "github.com/cilium/tetragon/pkg/testutils/observer"
	"github.com/cilium/tetragon/pkg/testutils/perfring"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/google/uuid"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/containerd/cgroups"
	cgroupsv2 "github.com/containerd/cgroups/v2"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func createCgroup(t *testing.T, dir string, pids ...uint64) policyfilter.CgroupID {
	cgMode := cgroups.Mode()
	var path string
	if cgMode == cgroups.Unified {
		cgroupFs := "/sys/fs/cgroup"
		res := cgroupsv2.Resources{}
		m, err := cgroupsv2.NewSystemd("/", dir, -1, &res)
		require.NoError(t, err)
		t.Cleanup(func() {
			m.DeleteSystemd()
		})
		for _, pid := range pids {
			err = m.AddProc(pid)
			require.NoError(t, err)
		}
		// Example: sys/fs/cgroup/TestNamespacedPolicies.cgroup1.20230302145438.slice
		path = filepath.Join(cgroupFs, dir)
		require.NoError(t, err)

	} else if cgMode == cgroups.Hybrid {
		cgroupFs := "/sys/fs/cgroup"
		slice := "system.slice"
		// NB(kkourt): this is just for our vmtests VM
		cmd := exec.Command("sudo", "mount", "-o", "remount,rw", cgroupFs)
		cmd.Run()
		control, err := cgroups.New(cgroups.V1, cgroups.Slice(slice, dir), &specs.LinuxResources{
			Devices: []specs.LinuxDeviceCgroup{},
			Memory:  &specs.LinuxMemory{},
			CPU:     &specs.LinuxCPU{},
			Pids:    &specs.LinuxPids{},
		})
		require.NoError(t, err)
		t.Cleanup(func() {
			control.Delete()
		})
		for _, pid := range pids {
			err = control.Add(cgroups.Process{Pid: int(pid)})
			require.NoError(t, err)
		}
		require.NoError(t, err)
		// Example: "/sys/fs/cgroup/memory/system.slice/TestNamespacedPolicies.cgroup1.20230302140421.slice"
		path = filepath.Join(cgroupFs, tgcgroups.GetCgrpControllerName(), slice, dir)
		require.NoError(t, err)
	} else {
		t.Skipf("Unsupported cgroup mode: %d", cgMode)
	}

	if path == "" {
		t.Fatal("createCgroup: unexpected error")
	}

	id, err := tgcgroups.GetCgroupIdFromPath(path)
	require.NoError(t, err, fmt.Sprintf("failed to get cgroup id for path=%s", path))
	t.Logf("cgroup path:%s cgroup id:%d", path, id)
	return policyfilter.CgroupID(id)
}

// TestNamespacedPolicies tests namespace filtering on tracepoints and kprobes
func TestNamespacedPolicies(t *testing.T) {
	testutils.CaptureLog(t, logger.GetLogger().(*logrus.Logger))
	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	// OK, first let's initialize some stuff!
	if err := observer.InitDataCache(1024); err != nil {
		t.Fatalf("observer.InitDataCache: %s", err)
	}
	option.Config.HubbleLib = tus.Conf().TetragonLib
	err := confmap.UpdateTgRuntimeConf(bpf.MapPrefixPath(), os.Getpid())
	require.NoError(t, err)

	policyfilter.TestingEnableAndReset(t)

	tus.LoadInitialSensor(t)
	tus.LoadSensor(t, testsensor.GetTestSensor())
	sm := tuo.GetTestSensorManager(t)

	// First, we create two lseek-pipe commands and add them to a different cgroup. See
	// contrib/tester-progs/go/lseek-pipe for details of how lseek-pipe wowkrs, but basically it
	// will take 3 lseek arguments its stdin, and exec a program that performs an lseek with
	// those arguments. Why exec you ask? Excellent question! We need an exec so that tetragon
	// can setup the cgroup ids on the execve_map which happens at exec().
	// (NB: an alternative option would be to use docker)
	lseekPipeCmd1 := testutils.NewLseekPipe(t, ctx)
	lseekPipeCmd2 := testutils.NewLseekPipe(t, ctx)
	cgDir1 := fmt.Sprintf("%s.cgroup1.%s.slice", t.Name(), time.Now().Format("20060102150405"))
	cgDir2 := fmt.Sprintf("%s.cgroup2.%s.slice", t.Name(), time.Now().Format("20060102150405"))
	cgID1 := createCgroup(t, cgDir1, uint64(lseekPipeCmd1.Pid()))
	cgID2 := createCgroup(t, cgDir2, uint64(lseekPipeCmd2.Pid()))

	// The idea of the test is to execute invalid lseek operations and see what events we
	// create. The first process will run an lseek with fd=-42 and whence=4444, and the second
	// one also with fd=-42 and whence=4445.
	whence1 := 4444
	whence2 := 4445
	bogusFD := -42
	lseekOps1 := func(t *testing.T) {
		t.Logf("running lseek (1):")
		res := lseekPipeCmd1.Lseek(bogusFD, 0, whence1)
		t.Logf("%s", res)
	}
	lseekOps2 := func(t *testing.T) {
		t.Logf("running lseek (2):")
		res := lseekPipeCmd2.Lseek(bogusFD, 0, whence2)
		t.Logf("%s", res)
	}

	// Next we will create two policies: a kprobe policy (kpPolicyConf) and a tracepoint policy
	// (tpPolicyConf)
	// both policies will do the same thing:
	// filter lseek calls based on the bogusFD, and record their whence value.
	// both policies are namespaced to namespace ns1
	kpSpec := v1alpha1.KProbeSpec{
		Call:    "sys_lseek",
		Return:  false,
		Syscall: true,
		ReturnArg: &v1alpha1.KProbeArg{
			Type: "int",
		},
		Args: []v1alpha1.KProbeArg{
			{Index: 0, Type: "int"},
			{Index: 2, Type: "int"},
		},
		Selectors: []v1alpha1.KProbeSelector{
			{MatchArgs: []v1alpha1.ArgSelector{{
				Index:    0,
				Operator: "Equal",
				Values:   []string{fmt.Sprintf("%d", bogusFD)},
			}}},
		},
	}
	kpPolicyConf := tracingpolicy.GenericTracingPolicyNamespaced{
		Metadata: v1.ObjectMeta{
			Name:      "lseek-test",
			Namespace: "ns1",
		},
		Spec: v1alpha1.TracingPolicySpec{
			KProbes: []v1alpha1.KProbeSpec{kpSpec},
		},
	}

	tpSpec := v1alpha1.TracepointSpec{
		Subsystem: "syscalls",
		Event:     "sys_enter_lseek",
		Args: []v1alpha1.KProbeArg{
			{Index: 5 /* fd */},
			{Index: 7 /* whence */},
		},
		Selectors: []v1alpha1.KProbeSelector{
			{MatchArgs: []v1alpha1.ArgSelector{{
				Index:    5,
				Operator: "Equal",
				// tracepoint specification defines fd as unsigned, so we need its
				// unsigned value for the filter:
				// (gdb) printf "%lu\n", -42
				// 18446744073709551574
				Values: []string{"18446744073709551574"},
			}}},
		},
	}
	tpPolicyConf := tracingpolicy.GenericTracingPolicyNamespaced{
		Metadata: v1.ObjectMeta{
			Name:      "lseek-test",
			Namespace: "ns1",
		},
		Spec: v1alpha1.TracingPolicySpec{
			Tracepoints: []v1alpha1.TracepointSpec{tpSpec},
		},
	}

	// this is our test function, it runs the two lseek operations and groups results based on
	// the whence value.
	runTest := func(expected map[int32]int) {
		res := perfring.RunTestEventReduce(
			t, ctx,
			func() {
				lseekOps1(t)
				lseekOps2(t)
			},
			perfring.FilterTestMessages,
			func(x notify.Message) *int32 {
				if kpEvent, ok := x.(*tracing.MsgGenericKprobeUnix); ok {
					arg, ok := kpEvent.Args[1].(tracingapi.MsgGenericKprobeArgInt)
					if ok {
						return &arg.Value
					}
				} else if tpEvent, ok := x.(*tracing.MsgGenericTracepointUnix); ok {
					arg, ok := tpEvent.Args[1].(uint64)
					if ok {
						// cast uint64 to int32 so that we can have a single
						// runTest function.
						x := int32(arg)
						return &x
					}
				} else if execEvent, ok := x.(*grpcexec.MsgExecveEventUnix); ok {
					if strings.HasSuffix(execEvent.Unix.Process.Filename, "lseek-pipe") {
						t.Logf("exec:%s %s, cgroupid:%d flags:%v", execEvent.Unix.Process.Filename, execEvent.Unix.Process.Args, execEvent.Unix.Msg.Kube.Cgrpid, execEvent.Unix.Process.Flags)
					}
				}
				return nil
			},
			func(v map[int32]int, k *int32) map[int32]int {
				if v == nil {
					v = make(map[int32]int)
				}
				if k != nil {
					v[*k]++
				}
				return v
			},
		)
		require.Equal(t, expected, res)
	}

	// Let's start testing!
	// First we add our kprobe policy
	err = sm.Manager.AddTracingPolicy(ctx, &kpPolicyConf)
	require.NoError(t, err)

	// Next, we pretend that our two cgroups are containers, and add them to the policyfilter
	// state. The first we add as if it is in "ns1" namespace, and the second as if it is in
	// "ns2" namespace. Hence, we expect to see events only from the first lseek-pipe program.
	pfState, err := policyfilter.GetState()
	t.Cleanup(func() { pfState.Close() })
	require.NoError(t, err)
	podId1 := uuid.New()
	podId2 := uuid.New()
	require.NoError(t, err)
	err = pfState.AddPodContainer(policyfilter.PodID(podId1), "ns1", "wl1", "kind1", nil,
		"pod1-container1", cgID1, "container-name1")
	require.NoError(t, err)
	err = pfState.AddPodContainer(policyfilter.PodID(podId2), "ns2", "wl2", "kind2", nil,
		"pod1-container2", cgID2, "container-name2")
	require.NoError(t, err)

	// Hence, we expect one event with whence value of 4444
	runTest(map[int32]int{4444: 1})

	// Let's delete the tracing policy, and check that we get no events
	err = sm.Manager.DeleteTracingPolicy(ctx, "lseek-test", "ns1")
	require.NoError(t, err)
	runTest(map[int32]int{})

	// try the same thing with the tracepoint policy
	err = sm.Manager.AddTracingPolicy(ctx, &tpPolicyConf)
	require.NoError(t, err)
	runTest(map[int32]int{4444: 1})

	// delete policy, and see that we still don't get any events
	err = sm.Manager.DeleteTracingPolicy(ctx, "lseek-test", "ns1")
	require.NoError(t, err)
	runTest(map[int32]int{})

	lseekPipeCmd1.Close()
	lseekPipeCmd2.Close()
}
