// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/grpc/tracing"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	lc "github.com/cilium/tetragon/pkg/matchers/listmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	smatcher "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/cilium/tetragon/pkg/sensors"
	testsensor "github.com/cilium/tetragon/pkg/sensors/test"
	"github.com/cilium/tetragon/pkg/testutils"
	tuo "github.com/cilium/tetragon/pkg/testutils/observer"
	"github.com/cilium/tetragon/pkg/testutils/perfring"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	_ "github.com/cilium/tetragon/pkg/sensors/exec"
)

var (
	whenceBogusValue = 4444
	fdBogusValue     = uint64(18446744073709551615) // -1
)

func TestMain(m *testing.M) {
	ec := tus.TestSensorsRun(m, "SensorTracing")
	os.Exit(ec)
}

// TestGenericTracepointSimple is a simple generic tracepoint test that creates a tracepoint for lseek()
func TestGenericTracepointSimple(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	lseekConf := v1alpha1.TracepointSpec{
		Subsystem: "syscalls",
		Event:     "sys_enter_lseek",
		Args: []v1alpha1.KProbeArg{
			{Index: 7},                 /* whence */
			{Index: 5, Type: "sint32"}, /* fd */
		},
	}

	spec := v1alpha1.TracingPolicySpec{
		Tracepoints: []v1alpha1.TracepointSpec{lseekConf},
		Lists:       []v1alpha1.ListSpec{},
	}

	// initialize observer
	obs, err := observertesthelper.GetDefaultObserver(t, ctx, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}

	sm := tuo.GetTestSensorManager(t)
	// create and add sensor
	policyInfo, err := newPolicyInfoFromSpec("", "policyName", policyfilter.NoFilterID, &spec, nil)
	require.NoError(t, err)
	sensor, err := createGenericTracepointSensor(&spec, "GtpLseekTest", policyInfo)
	if err != nil {
		t.Fatalf("failed to create generic tracepoint sensor: %s", err)
	}
	sm.AddAndEnableSensor(ctx, t, sensor, "GtpLseekTest")

	tpChecker := ec.NewProcessTracepointChecker("").
		WithSubsys(smatcher.Full("syscalls")).
		WithEvent(smatcher.Full("sys_enter_lseek")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithSizeArg(uint64(whenceBogusValue)),
				ec.NewKprobeArgumentChecker().WithIntArg(int32(fdBogusValue)), // -1
			))
	checker := ec.NewUnorderedEventChecker(tpChecker)

	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()
	unix.Seek(-1, 0, whenceBogusValue)
	time.Sleep(1000 * time.Millisecond)
	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

// doTestGenericTracepointPidFilter is a utility function for doing generic
// tracepoint tests. It filters events based on the test program's pid, so that
// we get more predictable results.
func doTestGenericTracepointPidFilter(t *testing.T, conf v1alpha1.TracepointSpec, selfOp func(), checkFn func(*tetragon.ProcessTracepoint) error) {
	if _, err := os.Stat("/sys/kernel/debug/tracing/events/syscalls"); os.IsNotExist(err) {
		t.Skip("cannot use syscall tracepoints (consider enabling CONFIG_FTRACE_SYSCALLS)")
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	pid := int(observertesthelper.GetMyPid())
	t.Logf("filtering for my pid (%d)", pid)
	pidSelector := v1alpha1.PIDSelector{
		Operator:       "In",
		IsNamespacePID: false,
		FollowForks:    true,
		Values:         []uint32{uint32(pid)},
	}

	if len(conf.Selectors) == 0 {
		conf.Selectors = make([]v1alpha1.KProbeSelector, 1)
	}
	conf.Selectors[0].MatchPIDs = append(conf.Selectors[0].MatchPIDs, pidSelector)
	obs, err := observertesthelper.GetDefaultObserver(t, ctx, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}

	spec := v1alpha1.TracingPolicySpec{
		Tracepoints: []v1alpha1.TracepointSpec{conf},
		Lists:       []v1alpha1.ListSpec{},
	}

	sm := tuo.GetTestSensorManager(t)
	// create and add sensor
	policyInfo, err := newPolicyInfoFromSpec("", "policyName", policyfilter.NoFilterID, &spec, nil)
	require.NoError(t, err)
	sensor, err := createGenericTracepointSensor(&spec, "GtpLseekTest", policyInfo)
	if err != nil {
		t.Fatalf("failed to create generic tracepoint sensor: %s", err)
	}
	sm.AddAndEnableSensor(ctx, t, sensor, "GtpLseekTest")
	testSensor := testsensor.GetTestSensor()
	sm.AddAndEnableSensor(ctx, t, testSensor, "testSensor")

	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()
	selfOp()
	testsensor.TestCheckerMarkEnd(t)
	t.Log("Marked test end")

	tpEventsNr := 0
	nextCheck := func(event ec.Event, _ *logrus.Logger) (bool, error) {
		switch tpEvent := event.(type) {
		case *tetragon.ProcessTracepoint:
			if err := checkFn(tpEvent); err != nil {
				return false, err
			}
			eventPid := tpEvent.Process.Pid.Value
			if int(eventPid) != pid {
				return false, fmt.Errorf("Unexpected pid=%d (filter is for pid %d)", eventPid, pid)
			}
			tpEventsNr++
			return false, nil
		default:
			return false, fmt.Errorf("not a tracepoint event: %T", tpEvent)

		}
	}
	finalCheck := func(_ *logrus.Logger) error {
		defer func() { tpEventsNr = 0 }()
		// NB: in some cases we get more than one events. I think this
		// might be due to -EINTR or similar return values.
		if tpEventsNr < 1 {
			return fmt.Errorf("Got %d events while expecting at least 1", tpEventsNr)
		}
		return nil
	}

	checker_ := ec.FnEventChecker{
		NextCheckFn:  nextCheck,
		FinalCheckFn: finalCheck,
	}
	checker := testsensor.NewTestChecker(&checker_)

	if err := jsonchecker.JsonTestCheck(t, checker); err != nil {
		t.Logf("error: %s", err)
		t.Fail()
	}
}

func TestGenericTracepointPidFilterLseek(t *testing.T) {
	tracepointConf := v1alpha1.TracepointSpec{
		Subsystem: "syscalls",
		Event:     "sys_enter_lseek",
	}

	op := func() {
		t.Logf("Calling lseek...\n")
		unix.Seek(-1, 0, whenceBogusValue)
	}

	check := func(_ *tetragon.ProcessTracepoint) error {
		return nil
	}

	doTestGenericTracepointPidFilter(t, tracepointConf, op, check)
}

func TestGenericTracepointArgFilterLseek(t *testing.T) {
	fd_u := int32(100)
	fd := 100
	whence_u := uint64(whenceBogusValue)
	whenceStr := fmt.Sprintf("%d", whenceBogusValue)
	whence := whenceBogusValue

	tracepointConf := v1alpha1.TracepointSpec{
		Subsystem: "syscalls",
		Event:     "sys_enter_lseek",
		Args: []v1alpha1.KProbeArg{
			{
				Index: 7, /* whence */
			},
			{
				Index: 5, Type: "sint32", /* fd */
			},
		},
		Selectors: []v1alpha1.KProbeSelector{
			{
				MatchArgs: []v1alpha1.ArgSelector{
					{
						Index:    7,
						Operator: "Equal",
						Values:   []string{whenceStr},
					},
				},
			},
		},
	}

	op := func() {
		t.Logf("Calling lseek...\n")
		unix.Seek(fd, 0, whence)
		unix.Seek(fd, 0, whence+1)
	}

	check := func(event *tetragon.ProcessTracepoint) error {
		if len(event.Args) != 2 {
			return fmt.Errorf("unexpected number of arguments: %d", len(event.Args))
		}
		arg0, ok := event.Args[0].GetArg().(*tetragon.KprobeArgument_SizeArg)
		if !ok {
			return fmt.Errorf("unexpected first arg: %s", event.Args[0])
		}
		xwhence := arg0.SizeArg
		if xwhence != whence_u {
			return fmt.Errorf("unexpected arg val. got:%d expecting:%d", xwhence, whence)
		}
		arg1, ok := event.Args[1].GetArg().(*tetragon.KprobeArgument_IntArg)
		if !ok {
			return fmt.Errorf("unexpected first arg: %s", event.Args[1])
		}
		xfd := arg1.IntArg
		if xfd != fd_u {
			return fmt.Errorf("unexpected arg val. got:%d expecting:%d", xfd, fd)
		}
		return nil
	}

	doTestGenericTracepointPidFilter(t, tracepointConf, op, check)
}

func TestGenericTracepointMeta(t *testing.T) {
	// We want to write to a file so we can filter by non-stdout fd and thus avoid
	// catching all the writes to test logs
	fd, err := syscall.Open("/tmp/testificate", syscall.O_CREAT|syscall.O_WRONLY, 0o644)
	assert.NoError(t, err)
	defer func() { syscall.Unlink("/tmp/testificate") }()

	tracepointConf := v1alpha1.TracepointSpec{
		Subsystem: "syscalls",
		Event:     "sys_enter_write",
		Args: []v1alpha1.KProbeArg{
			{
				Index: 5, /* fd */
			},
			{
				Index:        6,     /* char *buf */
				SizeArgIndex: 7 + 1, /* count */

			},
		},
		Selectors: []v1alpha1.KProbeSelector{{
			MatchArgs: []v1alpha1.ArgSelector{{
				Index:    5,
				Operator: "eq",
				Values:   []string{fmt.Sprint(fd)},
			}},
		}},
	}

	op := func() {
		syscall.Write(fd, []byte("hello world"))
	}

	check := func(event *tetragon.ProcessTracepoint) error {
		if event.Subsys != "syscalls" {
			return fmt.Errorf("Unexpected subsys: %s", event.Subsys)
		}
		if event.Event != "sys_enter_write" {
			return fmt.Errorf("Unexpected subsys: %s", event.Event)
		}
		if len(event.Args) != 2 {
			return fmt.Errorf("Expecting single argument, but got %d", len(event.Args))
		}
		arg1_, ok := event.Args[1].GetArg().(*tetragon.KprobeArgument_BytesArg)
		if !ok {
			return fmt.Errorf("Unexpected arg: %v", event.Args[1].GetArg())
		}
		arg1 := string(arg1_.BytesArg)
		if arg1 != "hello world" {
			return fmt.Errorf("Arg does not match \"hello world\"")
		}
		return nil
	}

	doTestGenericTracepointPidFilter(t, tracepointConf, op, check)
}

// TestRawSyscall checks raw_syscall tracepoints
// name: sys_enter
// ID: 346
// format:
//
//	field:unsigned short common_type;       offset:0;       size:2; signed:0;
//	field:unsigned char common_flags;       offset:2;       size:1; signed:0;
//	field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
//	field:int common_pid;   offset:4;   n    size:4; signed:1;
//
//	field:long id;  offset:8;       size:8; signed:1;
//	field:unsigned long args[6]
//
// print fmt: "NR %ld (%lx, %lx, %lx, %lx, %lx, %lx)", REC->id, REC->args[0], REC->args[1], REC->args[2], REC->args[3], REC->args[4], REC->args[5]
func TestGenericTracepointRawSyscall(t *testing.T) {
	tracepointConf := v1alpha1.TracepointSpec{
		Subsystem: "raw_syscalls",
		Event:     "sys_enter",
		Args: []v1alpha1.KProbeArg{
			v1alpha1.KProbeArg{
				Index: 4, /* id */
			},
			v1alpha1.KProbeArg{
				Index: 5, /* args */
			},
		},
		Selectors: []v1alpha1.KProbeSelector{
			{
				MatchArgs: []v1alpha1.ArgSelector{
					{
						Index:    4,
						Operator: "Equal",
						Values:   []string{fmt.Sprintf("%d", unix.SYS_LSEEK)},
					},
				},
			},
		},
	}
	op := func() {
		t.Logf("Calling lseek...\n")
		unix.Seek(-1, 0, whenceBogusValue)
	}

	check := func(event *tetragon.ProcessTracepoint) error {
		getSizeArg := func(i int) (uint64, error) {
			if len(event.Args) <= i {
				return 0, fmt.Errorf("args length is %d. Cannot retreieve args[%d]", len(event.Args), i)
			}

			arg := event.Args[i].GetArg()
			ret, ok := arg.(*tetragon.KprobeArgument_SizeArg)
			if !ok {
				return 0, fmt.Errorf("unexpected type of args[%d]: %T (%v) (expecting: SizeArg)", i, arg, arg)
			}

			return ret.SizeArg, nil
		}

		arg0, ok := event.Args[0].GetArg().(*tetragon.KprobeArgument_LongArg)
		if !ok {
			return fmt.Errorf("unexpected system call id: got:%d expecting:%d", arg0, unix.SYS_LSEEK)
		}
		sysID := arg0.LongArg
		if sysID != unix.SYS_LSEEK {
			return jsonchecker.NewDebugError(fmt.Errorf("unexpected arg val: got:%d expecting:%d", sysID, unix.SYS_LSEEK))
		}

		var err error
		args := make([]uint64, 3)
		for i := 0; i < 3; i++ {
			args[i], err = getSizeArg(i + 1)
			if err != nil {
				return err
			}
		}

		if args[0] == fdBogusValue && args[1] == 0 && args[2] == uint64(whenceBogusValue) {
			return nil
		}

		return fmt.Errorf("unexpected lseek args: %+v", args)
	}

	doTestGenericTracepointPidFilter(t, tracepointConf, op, check)
}

func TestLoadTracepointSensor(t *testing.T) {
	var sensorProgs = []tus.SensorProg{
		0: tus.SensorProg{Name: "generic_tracepoint_event", Type: ebpf.TracePoint},
		1: tus.SensorProg{Name: "generic_tracepoint_arg", Type: ebpf.TracePoint},
		2: tus.SensorProg{Name: "generic_tracepoint_process_event", Type: ebpf.TracePoint},
		3: tus.SensorProg{Name: "generic_tracepoint_filter", Type: ebpf.TracePoint},
		4: tus.SensorProg{Name: "generic_tracepoint_actions", Type: ebpf.TracePoint},
		5: tus.SensorProg{Name: "generic_tracepoint_output", Type: ebpf.TracePoint},
	}

	var sensorMaps = []tus.SensorMap{
		// all programs
		tus.SensorMap{Name: "process_call_heap", Progs: []uint{0, 1, 2, 3, 4, 5}},

		// all but generic_tracepoint_output
		tus.SensorMap{Name: "tp_calls", Progs: []uint{0, 1, 2, 3, 4}},

		// all but generic_tracepoint_event,generic_tracepoint_filter
		tus.SensorMap{Name: "retprobe_map", Progs: []uint{1, 2}},

		// generic_tracepoint_output
		tus.SensorMap{Name: "tcpmon_map", Progs: []uint{5}},

		// all kprobe but generic_tracepoint_filter
		tus.SensorMap{Name: "config_map", Progs: []uint{0, 2}},

		// generic_tracepoint_event
		tus.SensorMap{Name: "tg_conf_map", Progs: []uint{0}},
	}

	if config.EnableLargeProgs() {
		// shared with base sensor
		sensorMaps = append(sensorMaps, tus.SensorMap{Name: "execve_map", Progs: []uint{3, 4, 5}})

		// generic_tracepoint_event*,generic_tracepoint_filter
		sensorMaps = append(sensorMaps, tus.SensorMap{Name: "buffer_heap_map", Progs: []uint{2, 3}})
	} else {
		// shared with base sensor
		sensorMaps = append(sensorMaps, tus.SensorMap{Name: "execve_map", Progs: []uint{3}})

		// only generic_tracepoint_event*
		sensorMaps = append(sensorMaps, tus.SensorMap{Name: "buffer_heap_map", Progs: []uint{2}})
	}

	readHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "raw-syscalls"
spec:
  tracepoints:
    - subsystem: "raw_syscalls"
      event: "sys_enter"
      # args: add both the syscall id, and the array with the arguments
      args:
        - index: 4
        - index: 5
`

	var sens []*sensors.Sensor
	var err error

	readConfigHook := []byte(readHook)
	err = os.WriteFile(testConfigFile, readConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}
	sens, err = observertesthelper.GetDefaultSensorsWithFile(t, testConfigFile, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}

	tus.CheckSensorLoad(sens, sensorMaps, sensorProgs, t)

	sensi := make([]sensors.SensorIface, 0, len(sens))
	for _, s := range sens {
		sensi = append(sensi, s)
	}
	sensors.UnloadSensors(sensi)
}

func TestTracepointCloneThreads(t *testing.T) {
	testutils.CaptureLog(t, logger.GetLogger().(*logrus.Logger))
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	lseekConf := v1alpha1.TracepointSpec{
		Subsystem: "syscalls",
		Event:     "sys_enter_lseek",
		Args: []v1alpha1.KProbeArg{
			{Index: 7},                 /* whence */
			{Index: 5, Type: "sint32"}, /* fd */
		},
	}

	spec := v1alpha1.TracingPolicySpec{
		Tracepoints: []v1alpha1.TracepointSpec{lseekConf},
		Lists:       []v1alpha1.ListSpec{},
	}

	testBinPath := "contrib/tester-progs/threads-tester"
	testBin := testutils.RepoRootPath(testBinPath)
	testCmd := exec.CommandContext(ctx, testBin, "--sensor", "tracepoint")
	testPipes, err := testutils.NewCmdBufferedPipes(testCmd)
	if err != nil {
		t.Fatal(err)
	}
	defer testPipes.Close()

	// initialize observer
	t.Logf("starting observer")
	obs, err := observertesthelper.GetDefaultObserver(t, ctx, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}

	sm := tuo.GetTestSensorManager(t)
	// create and add sensor
	policyInfo, err := newPolicyInfoFromSpec("", "policyName", policyfilter.NoFilterID, &spec, nil)
	require.NoError(t, err)
	sensor, err := createGenericTracepointSensor(&spec, "GtpLseekTest", policyInfo)
	if err != nil {
		t.Fatalf("failed to create generic tracepoint sensor: %s", err)
	}
	sm.AddAndEnableSensor(ctx, t, sensor, "GtpLseekTest")

	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	cti := &testutils.ThreadTesterInfo{}
	if err := testCmd.Start(); err != nil {
		t.Fatal(err)
	}
	logWG := testPipes.ParseAndLogCmdOutput(t, cti.ParseLine, nil)
	logWG.Wait()
	if err := testCmd.Wait(); err != nil {
		t.Fatalf("command failed with %s. Context error: %v", err, ctx.Err())
	}

	cti.AssertPidsTids(t)

	parentCheck := ec.NewProcessChecker().
		WithBinary(smatcher.Suffix("threads-tester")).
		WithPid(cti.ParentPid).
		WithTid(cti.ParentTid)

	execCheck := ec.NewProcessExecChecker("").
		WithProcess(parentCheck)

	exitCheck := ec.NewProcessExitChecker("").
		WithProcess(parentCheck)

	child1Checker := ec.NewProcessChecker().
		WithBinary(smatcher.Suffix("threads-tester")).
		WithPid(cti.Child1Pid).
		WithTid(cti.Child1Tid)

	child1TpChecker := ec.NewProcessTracepointChecker("").
		WithSubsys(smatcher.Full("syscalls")).
		WithEvent(smatcher.Full("sys_enter_lseek")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithSizeArg(uint64(whenceBogusValue)),
				ec.NewKprobeArgumentChecker().WithIntArg(int32(fdBogusValue)), // -1
			)).WithProcess(child1Checker).WithParent(parentCheck)

	thread1Checker := ec.NewProcessChecker().
		WithBinary(smatcher.Suffix("threads-tester")).
		WithPid(cti.Thread1Pid).
		WithTid(cti.Thread1Tid)

	thread1TpChecker := ec.NewProcessTracepointChecker("").
		WithSubsys(smatcher.Full("syscalls")).
		WithEvent(smatcher.Full("sys_enter_lseek")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithSizeArg(uint64(whenceBogusValue)),
				ec.NewKprobeArgumentChecker().WithIntArg(int32(fdBogusValue)), // -1
			)).WithProcess(thread1Checker).WithParent(parentCheck)

	checker := ec.NewUnorderedEventChecker(execCheck, child1TpChecker, thread1TpChecker, exitCheck)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestTracepointForceType(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	lseekConfigHook_ := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "raw-syscalls"
spec:
  tracepoints:
  - subsystem: "syscalls"
    event: "sys_enter_lseek"
    message: "System call lseek tracepoint test"
    # args: add both the syscall id, and the array with the arguments
    args:
    # fd argument
    - index: 5
      type: "int32"
    # whence argument
    - index: 7
      type: "int32"
`

	lseekConfigHook := []byte(lseekConfigHook_)
	err := os.WriteFile(testConfigFile, lseekConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	testBinPath := "contrib/tester-progs/threads-tester"
	testBin := testutils.RepoRootPath(testBinPath)
	testCmd := exec.CommandContext(ctx, testBin, "--sensor", "tracepoint")
	testPipes, err := testutils.NewCmdBufferedPipes(testCmd)
	if err != nil {
		t.Fatal(err)
	}
	defer testPipes.Close()

	cti := &testutils.ThreadTesterInfo{}
	if err := testCmd.Start(); err != nil {
		t.Fatal(err)
	}
	logWG := testPipes.ParseAndLogCmdOutput(t, cti.ParseLine, nil)
	logWG.Wait()
	if err := testCmd.Wait(); err != nil {
		t.Fatalf("command failed with %s. Context error: %v", err, ctx.Err())
	}

	cti.AssertPidsTids(t)

	parentCheck := ec.NewProcessChecker().
		WithBinary(smatcher.Suffix("threads-tester")).
		WithPid(cti.ParentPid).
		WithTid(cti.ParentTid)

	execCheck := ec.NewProcessExecChecker("").
		WithProcess(parentCheck)

	exitCheck := ec.NewProcessExitChecker("").
		WithProcess(parentCheck)

	child1Checker := ec.NewProcessChecker().
		WithBinary(smatcher.Suffix("threads-tester")).
		WithPid(cti.Child1Pid).
		WithTid(cti.Child1Tid)

	child1TpChecker := ec.NewProcessTracepointChecker("").
		WithSubsys(smatcher.Full("syscalls")).
		WithEvent(smatcher.Full("sys_enter_lseek")).
		WithMessage(sm.Full("System call lseek tracepoint test")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(int32(fdBogusValue)), // -1
				ec.NewKprobeArgumentChecker().WithIntArg(int32(whenceBogusValue)),
			)).WithProcess(child1Checker).WithParent(parentCheck)

	thread1Checker := ec.NewProcessChecker().
		WithBinary(smatcher.Suffix("threads-tester")).
		WithPid(cti.Thread1Pid).
		WithTid(cti.Thread1Tid)

	thread1TpChecker := ec.NewProcessTracepointChecker("").
		WithSubsys(smatcher.Full("syscalls")).
		WithEvent(smatcher.Full("sys_enter_lseek")).
		WithMessage(sm.Full("System call lseek tracepoint test")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(int32(fdBogusValue)), // -1
				ec.NewKprobeArgumentChecker().WithIntArg(int32(whenceBogusValue)),
			)).WithProcess(thread1Checker).WithParent(parentCheck)

	checker := ec.NewUnorderedEventChecker(execCheck, child1TpChecker, thread1TpChecker, exitCheck)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestStringTracepoint(t *testing.T) {
	testutils.CaptureLog(t, logger.GetLogger().(*logrus.Logger))
	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	mypid := int(observertesthelper.GetMyPid())
	t.Logf("filtering for my pid (%d)", mypid)

	spec := &v1alpha1.TracingPolicySpec{
		Tracepoints: []v1alpha1.TracepointSpec{{
			Subsystem: "syscalls",
			Event:     "sys_enter_mkdirat",
			Args: []v1alpha1.KProbeArg{{
				Index: 4,
			}, {
				Index: 6,
				Type:  "string",
			}},
			/*
				Selectors: []v1alpha1.KProbeSelector{{
					MatchPIDs: []v1alpha1.PIDSelector{{
						Operator:    "In",
						FollowForks: true,
						Values:      []uint32{uint32(mypid)},
					}},
				}},
			*/
		}},
	}

	loadGenericSensorTest(t, spec)
	t0 := time.Now()
	loadElapsed := time.Since(t0)
	t.Logf("loading sensors took: %s\n", loadElapsed)

	countPizza := 0
	eventFn := func(ev notify.Message) error {
		if tpEvent, ok := ev.(*tracing.MsgGenericTracepointUnix); ok {
			if tpEvent.Event != "sys_enter_mkdirat" {
				return fmt.Errorf("unexpected tracepoint event, %s:%s", tpEvent.Subsys, tpEvent.Event)
			}
			arg := tpEvent.Args[1].(string)
			if strings.Contains(arg, "pizzaisthebest") {
				countPizza++
			}
		}
		return nil
	}

	ops := func() {
		// NB: unix.Mkdir uses unix.Mkdirat, so make things explicit
		unix.Mkdirat(unix.AT_FDCWD, "/tmp/pizzaisthebest", 0777)
		os.Remove("/tmp/pizzaisthebest")
	}

	perfring.RunTest(t, ctx, ops, eventFn)
	require.Equal(t, 1, countPizza, "expected events with 'pizzaisthebest'")
}

func testListSyscallsDupsRange(t *testing.T, checker *eventchecker.UnorderedEventChecker, configHook string) {
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

	for i := 9900; i < 9930; i++ {
		syscall.Dup(i)
	}

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestTracepointListSyscallDupsRange(t *testing.T) {
	if !kernels.MinKernelVersion("5.3.0") {
		t.Skip("TestCopyFd requires at least 5.3.0 version")
	}
	myPid := observertesthelper.GetMyPid()
	pidStr := strconv.Itoa(int(myPid))
	configHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "sys-write"
spec:
  lists:
  - name: "test"
    type: "syscalls"
    values:
    - "sys_dup"
  tracepoints:
  - subsystem: "raw_syscalls"
    event: "sys_enter"
    args:
    - index: 4
      type: "syscall64"
    - index: 5
      type: "uint64"
    selectors:
    - matchPIDs:
      - operator: In
        followForks: true
        isNamespacePID: false
        values:
        - ` + pidStr + `
      matchArgs:
      - index: 0
        operator: "InMap"
        values:
        - "list:test"
      - index: 1
        operator: "InMap"
        values:
        - 9910:9920
`

	// The test hooks raw tracepoint and uses InMap operator to filter
	// for dup syscall and for fd in range 9910 to 9920.

	checker := ec.NewUnorderedEventChecker()

	for i := 9910; i < 9920; i++ {
		tpCheckerDup := ec.NewProcessTracepointChecker("").
			WithArgs(ec.NewKprobeArgumentListMatcher().
				WithOperator(lc.Ordered).
				WithValues(
					ec.NewKprobeArgumentChecker().WithSyscallId(mkSysIDChecker(t, unix.SYS_DUP)),
					ec.NewKprobeArgumentChecker().WithSizeArg(uint64(i)),
				))

		checker.AddChecks(tpCheckerDup)
	}

	testListSyscallsDupsRange(t, checker, configHook)
}
