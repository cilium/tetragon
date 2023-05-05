// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"context"
	"fmt"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/kernels"
	lc "github.com/cilium/tetragon/pkg/matchers/listmatcher"
	smatcher "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors"
	testsensor "github.com/cilium/tetragon/pkg/sensors/test"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
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

	lseekConf := GenericTracepointConf{
		Subsystem: "syscalls",
		Event:     "sys_enter_lseek",
		Args: []v1alpha1.KProbeArg{
			{Index: 7}, /* whence */
			{Index: 5}, /* fd */
		},
	}

	// initialize observer
	obs, err := observer.GetDefaultObserver(t, ctx, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}

	sm := tus.StartTestSensorManager(ctx, t)
	// create and add sensor
	sensor, err := createGenericTracepointSensor("GtpLseekTest", []GenericTracepointConf{lseekConf}, policyfilter.NoFilterID, "policyName")
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
				ec.NewKprobeArgumentChecker().WithSizeArg(fdBogusValue), // -1
			))
	checker := ec.NewUnorderedEventChecker(tpChecker)

	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()
	unix.Seek(-1, 0, whenceBogusValue)
	time.Sleep(1000 * time.Millisecond)
	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

// doTestGenericTracepointPidFilter is a utility function for doing generic
// tracepoint tests. It filters events based on the test program's pid, so that
// we get more predictable results.
func doTestGenericTracepointPidFilter(t *testing.T, conf GenericTracepointConf, selfOp func(), checkFn func(*tetragon.ProcessTracepoint) error) {
	if _, err := os.Stat("/sys/kernel/debug/tracing/events/syscalls"); os.IsNotExist(err) {
		t.Skip("cannot use syscall tracepoints (consider enabling CONFIG_FTRACE_SYSCALLS)")
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	pid := int(observer.GetMyPid())
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
	obs, err := observer.GetDefaultObserver(t, ctx, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}

	sm := tus.StartTestSensorManager(ctx, t)
	// create and add sensor
	sensor, err := createGenericTracepointSensor("GtpLseekTest", []GenericTracepointConf{conf}, policyfilter.NoFilterID, "policyName")
	if err != nil {
		t.Fatalf("failed to create generic tracepoint sensor: %s", err)
	}
	sm.AddAndEnableSensor(ctx, t, sensor, "GtpLseekTest")
	testSensor := testsensor.GetTestSensor()
	sm.AddAndEnableSensor(ctx, t, testSensor, "testSensor")

	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()
	selfOp()
	testsensor.TestCheckerMarkEnd(t)
	t.Log("Marked test end")

	tpEventsNr := 0
	nextCheck := func(event ec.Event, l *logrus.Logger) (bool, error) {
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
	finalCheck := func(l *logrus.Logger) error {
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
	tracepointConf := GenericTracepointConf{
		Subsystem: "syscalls",
		Event:     "sys_enter_lseek",
	}

	op := func() {
		t.Logf("Calling lseek...\n")
		unix.Seek(-1, 0, whenceBogusValue)
	}

	check := func(event *tetragon.ProcessTracepoint) error {
		return nil
	}

	doTestGenericTracepointPidFilter(t, tracepointConf, op, check)
}

func TestGenericTracepointArgFilterLseek(t *testing.T) {
	fd_u := uint64(100)
	fd := 100
	whence_u := uint64(whenceBogusValue)
	whenceStr := fmt.Sprintf("%d", whenceBogusValue)
	whence := whenceBogusValue

	tracepointConf := GenericTracepointConf{
		Subsystem: "syscalls",
		Event:     "sys_enter_lseek",
		Args: []v1alpha1.KProbeArg{
			{
				Index: 7, /* whence */
			},
			{
				Index: 5, /* fd */
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
		arg1, ok := event.Args[1].GetArg().(*tetragon.KprobeArgument_SizeArg)
		if !ok {
			return fmt.Errorf("unexpected first arg: %s", event.Args[1])
		}
		xfd := arg1.SizeArg
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

	tracepointConf := GenericTracepointConf{
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
	tracepointConf := GenericTracepointConf{
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
		0:  tus.SensorProg{Name: "generic_tracepoint_event", Type: ebpf.TracePoint},
		1:  tus.SensorProg{Name: "generic_tracepoint_arg1", Type: ebpf.TracePoint},
		2:  tus.SensorProg{Name: "generic_tracepoint_arg2", Type: ebpf.TracePoint},
		3:  tus.SensorProg{Name: "generic_tracepoint_arg3", Type: ebpf.TracePoint},
		4:  tus.SensorProg{Name: "generic_tracepoint_arg4", Type: ebpf.TracePoint},
		5:  tus.SensorProg{Name: "generic_tracepoint_arg5", Type: ebpf.TracePoint},
		6:  tus.SensorProg{Name: "generic_tracepoint_event0", Type: ebpf.TracePoint},
		7:  tus.SensorProg{Name: "generic_tracepoint_event1", Type: ebpf.TracePoint},
		8:  tus.SensorProg{Name: "generic_tracepoint_event2", Type: ebpf.TracePoint},
		9:  tus.SensorProg{Name: "generic_tracepoint_event3", Type: ebpf.TracePoint},
		10: tus.SensorProg{Name: "generic_tracepoint_event4", Type: ebpf.TracePoint},
		11: tus.SensorProg{Name: "generic_tracepoint_filter", Type: ebpf.TracePoint},
		12: tus.SensorProg{Name: "generic_tracepoint_actions", Type: ebpf.TracePoint},
		13: tus.SensorProg{Name: "generic_tracepoint_output", Type: ebpf.TracePoint},
	}

	var sensorMaps = []tus.SensorMap{
		// all programs
		tus.SensorMap{Name: "tp_heap", Progs: []uint{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}},

		// all but generic_tracepoint_output
		tus.SensorMap{Name: "tp_calls", Progs: []uint{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}},

		// only generic_tracepoint_event*
		tus.SensorMap{Name: "buffer_heap_map", Progs: []uint{6, 7, 8, 9, 10}},

		// all but generic_tracepoint_event,generic_tracepoint_filter
		tus.SensorMap{Name: "retprobe_map", Progs: []uint{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}},

		// generic_tracepoint_output
		tus.SensorMap{Name: "tcpmon_map", Progs: []uint{13}},

		// all kprobe but generic_tracepoint_filter
		tus.SensorMap{Name: "config_map", Progs: []uint{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}},
	}

	if kernels.EnableLargeProgs() {
		// shared with base sensor
		sensorMaps = append(sensorMaps, tus.SensorMap{Name: "execve_map", Progs: []uint{0, 1, 2, 3, 4, 5, 11, 13}})
	} else {
		// shared with base sensor
		sensorMaps = append(sensorMaps, tus.SensorMap{Name: "execve_map", Progs: []uint{0, 1, 2, 3, 4, 5, 11}})
	}

	readHook := `
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
	sens, err = observer.GetDefaultSensorsWithFile(t, context.TODO(), testConfigFile, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}

	tus.CheckSensorLoad(sens, sensorMaps, sensorProgs, t)

	sensors.UnloadAll()
}
