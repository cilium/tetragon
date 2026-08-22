// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/containerd/cgroups/v3"
	cgroupsv1 "github.com/containerd/cgroups/v3/cgroup1"
	cgroupsv2 "github.com/containerd/cgroups/v3/cgroup2"
	"github.com/google/uuid"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/tetragon/pkg/api/tracingapi"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/build"
	tgcgroups "github.com/cilium/tetragon/pkg/cgroups"
	"github.com/cilium/tetragon/pkg/config"
	grpcexec "github.com/cilium/tetragon/pkg/grpc/exec"
	"github.com/cilium/tetragon/pkg/grpc/tracing"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/podhelpers"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/cilium/tetragon/pkg/sensors/config/confmap"
	testsensor "github.com/cilium/tetragon/pkg/sensors/test"
	"github.com/cilium/tetragon/pkg/testutils"
	tuo "github.com/cilium/tetragon/pkg/testutils/observer"
	"github.com/cilium/tetragon/pkg/testutils/perfring"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

func createCgroup(t *testing.T, dir string, pids ...uint64) policyfilter.CgroupID {
	cgMode := cgroups.Mode()
	var path string
	switch cgMode {
	case cgroups.Unified:
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

	case cgroups.Hybrid:
		cgroupFs := "/sys/fs/cgroup"
		slice := "system.slice"
		// NB(kkourt): this is just for our vmtests VM
		cmd := exec.Command("sudo", "mount", "-o", "remount,rw", cgroupFs)
		cmd.Run()
		control, err := cgroupsv1.New(cgroupsv1.Slice(slice, dir), &specs.LinuxResources{
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
			err = control.Add(cgroupsv1.Process{Pid: int(pid)})
			require.NoError(t, err)
		}
		require.NoError(t, err)
		// Example: "/sys/fs/cgroup/memory/system.slice/TestNamespacedPolicies.cgroup1.20230302140421.slice"
		path = filepath.Join(cgroupFs, tgcgroups.GetCgrpControllerName(), slice, dir)
		require.NoError(t, err)
	default:
		t.Skipf("Unsupported cgroup mode: %d", cgMode)
	}

	if path == "" {
		t.Fatal("createCgroup: unexpected error")
	}

	id, err := tgcgroups.GetCgroupIdFromPath(path)
	require.NoError(t, err, "failed to get cgroup id for path="+path)
	t.Logf("cgroup path:%s cgroup id:%d", path, id)
	return policyfilter.CgroupID(id)
}

// TestNamespacedPolicies tests namespace filtering on tracepoints and kprobes
func TestNamespacedPolicies(t *testing.T) {
	build.SkipIfK8sDisabled(t)
	oldEnableK8s := option.Config.EnableK8s
	option.Config.EnableK8s = true
	t.Cleanup(func() {
		option.Config.EnableK8s = oldEnableK8s
	})

	testutils.CaptureLog(t, logger.GetLogger())
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
				Values:   []string{strconv.Itoa(bogusFD)},
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
						return new(int32(arg))
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
	err = pfState.AddPodContainer(policyfilter.PodID(podId1), "ns1", nil,
		"pod1-container1", cgID1, podhelpers.ContainerInfo{Name: "container-name1", Repo: "container-repo1"})
	require.NoError(t, err)
	err = pfState.AddPodContainer(policyfilter.PodID(podId2), "ns2", nil,
		"pod1-container2", cgID2, podhelpers.ContainerInfo{Name: "container-name2", Repo: "container-repo2"})
	require.NoError(t, err)

	// Hence, we expect one event with whence value of 4444
	runTest(map[int32]int{4444: 1})

	// Let's delete the tracing policy, and check that we get no events
	err = sm.Manager.DeleteTracingPolicy(ctx, "lseek-test", "ns1", kpPolicyConf.TpDomain())
	require.NoError(t, err)
	runTest(map[int32]int{})

	// try the same thing with the tracepoint policy
	err = sm.Manager.AddTracingPolicy(ctx, &tpPolicyConf)
	require.NoError(t, err)
	runTest(map[int32]int{4444: 1})

	// delete policy, and see that we still don't get any events
	err = sm.Manager.DeleteTracingPolicy(ctx, "lseek-test", "ns1", kpPolicyConf.TpDomain())
	require.NoError(t, err)
	runTest(map[int32]int{})

	lseekPipeCmd1.Close()
	lseekPipeCmd2.Close()
}

// TestUprobeNamespacedPolicy tests namespace filtering on uprobes
func TestUprobeNamespacedPolicy(t *testing.T) {
	build.SkipIfK8sDisabled(t)
	oldEnableK8s := option.Config.EnableK8s
	option.Config.EnableK8s = true
	t.Cleanup(func() {
		option.Config.EnableK8s = oldEnableK8s
	})

	testutils.CaptureLog(t, logger.GetLogger())
	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	policyfilter.TestingEnableAndReset(t)
	sm := tuo.GetTestSensorManager(t)

	// A namespaced policy may not attach a uprobe: its target is resolved in the
	// agent's host mount namespace, so it is rejected at load.
	upPolicyConf := tracingpolicy.GenericTracingPolicyNamespaced{
		Metadata: v1.ObjectMeta{
			Name:      "uprobe-test",
			Namespace: "ns1",
		},
		Spec: v1alpha1.TracingPolicySpec{
			UProbes: []v1alpha1.UProbeSpec{{
				Path:    testutils.RepoRootPath("contrib/tester-progs/lseek-pipe"),
				Symbols: []string{"main.main"},
			}},
		},
	}
	err := sm.Manager.AddTracingPolicy(ctx, &upPolicyConf)
	require.ErrorContains(t, err, "uprobe")
}

func TestLsmNamespacedPolicyClearsPostState(t *testing.T) {
	if !bpf.HasLSMPrograms() || !config.EnableLargeProgs() {
		t.Skip("BPF LSM programs are not supported on this kernel")
	}
	build.SkipIfK8sDisabled(t)

	oldEnableK8s := option.Config.EnableK8s
	option.Config.EnableK8s = true
	t.Cleanup(func() {
		option.Config.EnableK8s = oldEnableK8s
	})

	testutils.CaptureLog(t, logger.GetLogger())
	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	err := observer.InitDataCache(1024)
	require.NoError(t, err)
	option.Config.HubbleLib = tus.Conf().TetragonLib
	err = confmap.UpdateTgRuntimeConf(bpf.MapPrefixPath(), os.Getpid())
	require.NoError(t, err)

	policyfilter.TestingEnableAndReset(t)

	tus.LoadInitialSensor(t)
	tus.LoadSensor(t, testsensor.GetTestSensor())
	sm := tuo.GetTestSensorManager(t)

	matchingProcess := newCgroupShell(t, ctx)
	nonMatchingProcess := newCgroupShell(t, ctx)

	var availableCPUs unix.CPUSet
	require.NoError(t, unix.SchedGetaffinity(0, &availableCPUs))
	cpu := -1
	for i := 0; i < 1024; i++ {
		if availableCPUs.IsSet(i) {
			cpu = i
			break
		}
	}
	require.NotEqual(t, -1, cpu, "no available CPU found")

	var affinity unix.CPUSet
	affinity.Set(cpu)
	require.NoError(t, unix.SchedSetaffinity(matchingProcess.pid(), &affinity))
	require.NoError(t, unix.SchedSetaffinity(nonMatchingProcess.pid(), &affinity))

	now := time.Now().Format("20060102150405")
	matchingCgID := createCgroup(t, fmt.Sprintf("%s.matching.%s.slice", t.Name(), now), uint64(matchingProcess.pid()))
	nonMatchingCgID := createCgroup(t, fmt.Sprintf("%s.nonmatching.%s.slice", t.Name(), now), uint64(nonMatchingProcess.pid()))

	pfState, err := policyfilter.GetState()
	require.NoError(t, err)
	t.Cleanup(func() { pfState.Close() })

	targetFile := filepath.Join(t.TempDir(), "target")
	require.NoError(t, os.WriteFile(targetFile, []byte("test"), 0o600))

	policy := &tracingpolicy.GenericTracingPolicyNamespaced{
		Metadata: v1.ObjectMeta{
			Name:      "lsm-policy-filter-test",
			Namespace: "ns1",
		},
		Spec: v1alpha1.TracingPolicySpec{
			LsmHooks: []v1alpha1.LsmHookSpec{{
				Hook: "file_open",
				Args: []v1alpha1.KProbeArg{{Index: 0, Type: "file"}},
				Selectors: []v1alpha1.KProbeSelector{{
					MatchArgs: []v1alpha1.ArgSelector{{
						Index:    0,
						Operator: "Equal",
						Values:   []string{targetFile},
					}},
					MatchActions: []v1alpha1.ActionSelector{{Action: "Post"}},
				}},
			}},
		},
	}
	err = sm.Manager.AddTracingPolicy(ctx, policy)
	require.NoError(t, err)
	t.Cleanup(func() {
		sm.Manager.DeleteTracingPolicy(ctx, policy.TpName(), policy.TpNamespace(), policy.TpDomain())
	})
	err = pfState.AddPodContainer(policyfilter.PodID(uuid.New()), "ns1", nil,
		"matching-container", matchingCgID, podhelpers.ContainerInfo{Name: "matching-container", Repo: "test"})
	require.NoError(t, err)
	err = pfState.AddPodContainer(policyfilter.PodID(uuid.New()), "ns2", nil,
		"non-matching-container", nonMatchingCgID, podhelpers.ContainerInfo{Name: "non-matching-container", Repo: "test"})
	require.NoError(t, err)

	events := perfring.RunTestEvents(t, ctx, func() {
		matchingProcess.run(t, fmt.Sprintf("cat %q >/dev/null", targetFile))
		for range 5 {
			nonMatchingProcess.run(t, "cat /dev/null >/dev/null")
		}
	})

	count := 0
	for _, event := range events {
		if lsm, ok := event.(*tracing.MsgGenericLsmUnix); ok &&
			lsm.Hook == "file_open" && lsm.PolicyName == policy.TpName() {
			count++
		}
	}
	require.Equal(t, 1, count)
}

// cgroupShell is a long-running shell used to run commands from a cgroup.
type cgroupShell struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
}

//revive:disable:context-as-argument
func newCgroupShell(t *testing.T, ctx context.Context) *cgroupShell {
	cmd := exec.CommandContext(ctx, "/bin/sh")
	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		stdin.Close()
		cmd.Wait()
	})
	return &cgroupShell{cmd: cmd, stdin: stdin, stdout: bufio.NewReader(stdout)}
}

//revive:enable:context-as-argument

func (shell *cgroupShell) pid() int {
	return shell.cmd.Process.Pid
}

// run executes command and returns only after it has exited.
func (shell *cgroupShell) run(t *testing.T, command string) {
	_, err := fmt.Fprintf(shell.stdin, "%s; echo done\n", command)
	require.NoError(t, err)
	line, err := shell.stdout.ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "done\n", line)
}

// TestUsdtNamespacedPolicy verifies a namespaced policy may not attach a usdt
// probe.
func TestUsdtNamespacedPolicy(t *testing.T) {
	build.SkipIfK8sDisabled(t)
	oldEnableK8s := option.Config.EnableK8s
	option.Config.EnableK8s = true
	t.Cleanup(func() {
		option.Config.EnableK8s = oldEnableK8s
	})

	testutils.CaptureLog(t, logger.GetLogger())
	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	policyfilter.TestingEnableAndReset(t)
	sm := tuo.GetTestSensorManager(t)

	// A namespaced policy may not attach a usdt probe: its target is resolved in
	// the agent's host mount namespace, so it is rejected at load.
	usdtPolicyConf := tracingpolicy.GenericTracingPolicyNamespaced{
		Metadata: v1.ObjectMeta{
			Name:      "usdt-test",
			Namespace: "ns1",
		},
		Spec: v1alpha1.TracingPolicySpec{
			Usdts: []v1alpha1.UsdtSpec{{
				Path:     testutils.RepoRootPath("contrib/tester-progs/usdt"),
				Provider: "test",
				Name:     "usdt0",
			}},
		},
	}
	err := sm.Manager.AddTracingPolicy(ctx, &usdtPolicyConf)
	require.ErrorContains(t, err, "usdt")
}
