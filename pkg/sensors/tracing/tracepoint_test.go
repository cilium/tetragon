// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/tetragon/api/v1/fgs"
	"github.com/cilium/tetragon/pkg/bpf"
	ec "github.com/cilium/tetragon/pkg/eventchecker"
	"github.com/cilium/tetragon/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/testutils"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"

	_ "github.com/cilium/tetragon/pkg/sensors/exec"
)

var (
	selfBinary   string
	fgsLib       string
	cmdWaitTime  time.Duration
	verboseLevel int

	tracepointTestDir = "/sys/fs/bpf/testObserver/"
)

func init() {
	flag.StringVar(&fgsLib, "bpf-lib", "../../../bpf/objs/", "hubble lib directory (location of btf file and bpf objs). Will be overridden by an FGS_LIB env variable.")
	flag.DurationVar(&cmdWaitTime, "command-wait", 20000*time.Millisecond, "duration to wait for fgs to gather logs from commands")
	flag.IntVar(&verboseLevel, "verbosity-level", 0, "verbosity level of verbose mode. (Requires verbose mode to be enabled.)")
}

func TestMain(m *testing.M) {
	flag.Parse()
	bpf.CheckOrMountFS("")
	bpf.CheckOrMountDebugFS()
	bpf.ConfigureResourceLimits()
	bpf.SetMapPrefix("testObserver")
	selfBinary = filepath.Base(os.Args[0])
	exitCode := m.Run()
	os.Exit(exitCode)
}

// TestGenericTracepointSimple is a simple generic tracepoint test that creates a tracepoint for lseek()
func TestGenericTracepointSimple(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
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
	obs, err := observer.GetDefaultObserver(t, fgsLib)
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}

	// We do not call observer.Start(), so we need to start the sensor controller
	sm, err := sensors.StartSensorManager(tracepointTestDir, tracepointTestDir, "")
	if err != nil {
		t.Fatalf("startSensorController failed: %s", err)
	}
	defer func() {
		err := sm.StopSensorManager(ctx)
		if err != nil {
			fmt.Printf("stopSensorController failed: %s\n", err)
		}
	}()

	// create and add sensor
	sensor, err := createGenericTracepointSensor([]GenericTracepointConf{lseekConf})
	if err != nil {
		t.Fatalf("failed to create generic tracepoint sensor: %s", err)
	}
	sensorName := "GtpLseekTest"
	if err := sm.AddSensor(ctx, sensorName, sensor); err != nil {
		t.Fatalf("failed to add generic tracepoint sensor: %s", err)
	}
	defer func() {
		sm.RemoveSensor(ctx, sensorName)
	}()
	if err := sm.EnableSensor(ctx, sensorName); err != nil {
		t.Fatalf("EnableSensor error: %s", err)
	}
	defer func() {
		sm.DisableSensor(ctx, sensorName)
	}()

	tpChecker := ec.NewTracepointChecker().
		WithSubsys("syscalls").
		WithEvent("sys_enter_lseek").
		WithArgs([]ec.GenericArgChecker{
			ec.GenericArgSizeCheck(4444),
			ec.GenericArgSizeCheck(18446744073709551615), // -1
		})

	checker := ec.NewSingleMultiResponseChecker(
		ec.NewTracepointEventChecker().
			HasTracepoint(tpChecker).
			End(),
	)

	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()
	unix.Seek(-1, 0, 4444)
	time.Sleep(1000 * time.Millisecond)
	err = observer.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func doTestGenericTracepointPidFilter(t *testing.T, conf GenericTracepointConf, selfOp func(), checkFn func(*fgs.ProcessTracepoint) error) {
	defer func() {
		if t.Failed() {
			testutils.KeepExportFile(t)
		}
	}()

	if _, err := os.Stat("/sys/kernel/debug/tracing/events/syscalls"); os.IsNotExist(err) {
		t.Skip("cannot use syscall tracepoints (consider enabling CONFIG_FTRACE_SYSCALLS)")
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
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
	obs, err := observer.GetDefaultObserver(t, fgsLib)
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}
	// We do not call observer.Start(), so we need to start the sensor controller
	sm, err := sensors.StartSensorManager(tracepointTestDir, tracepointTestDir, "")
	if err != nil {
		t.Fatalf("startSensorController failed: %s", err)
	}
	defer func() {
		err := sm.StopSensorManager(ctx)
		if err != nil {
			fmt.Printf("stopSensorController failed: %s\n", err)
		}
	}()

	// create and add sensor
	sensor, err := createGenericTracepointSensor([]GenericTracepointConf{conf})
	if err != nil {
		t.Fatalf("failed to create generic tracepoint sensor: %s", err)
	}
	sensorName := "GtpLseekTest"
	if err := sm.AddSensor(ctx, sensorName, sensor); err != nil {
		t.Fatalf("failed to add generic tracepoint sensor: %s", err)
	}
	defer func() {
		sm.RemoveSensor(ctx, sensorName)
	}()
	if err := sm.EnableSensor(ctx, sensorName); err != nil {
		t.Fatalf("EnableSensor error: %s", err)
	}
	defer func() {
		sm.DisableSensor(ctx, sensorName)
	}()

	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()
	selfOp()

	tpEventsNr := 0
	nextCheck := func(event *fgs.GetEventsResponse, l ec.Logger) (bool, error) {
		switch tpEvent := event.Event.(type) {
		case *fgs.GetEventsResponse_ProcessTracepoint:
			if err := checkFn(tpEvent.ProcessTracepoint); err != nil {
				return false, err
			}
			eventPid := tpEvent.ProcessTracepoint.Process.Pid.Value
			if int(eventPid) != pid {
				return false, fmt.Errorf("Unexpected pid=%d (filter is for pid %d)", eventPid, pid)
			}
			tpEventsNr++
			return false, nil
		default:
			return false, fmt.Errorf("not a tracepoint event: %T", tpEvent)

		}
	}
	finalCheck := func(l ec.Logger) error {
		// NB: in some cases we get more than one events. I think this
		// might be due to -EINTR or similar return values.
		if tpEventsNr < 1 {
			return fmt.Errorf("Got %d events while expecting at least 1", tpEventsNr)
		}
		return nil
	}
	Reset := func() {
		tpEventsNr = 0
	}
	checker := ec.MultiResponseCheckerFns{
		NextCheckFn:  nextCheck,
		FinalCheckFn: finalCheck,
		ResetFn:      Reset,
	}

	if err := observer.JsonTestCheck(t, &checker); err != nil {
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
		fmt.Printf("Calling lseek...\n")
		unix.Seek(-1, 0, 4444)
	}

	check := func(event *fgs.ProcessTracepoint) error {
		return nil
	}

	doTestGenericTracepointPidFilter(t, tracepointConf, op, check)
}

func TestGenericTracepointArgFilterLseek(t *testing.T) {
	fd_u := uint64(100)
	fd := 100
	whence_u := uint64(4444)
	whenceStr := "4444"
	whence := 4444

	tracepointConf := GenericTracepointConf{
		Subsystem: "syscalls",
		Event:     "sys_enter_lseek",
		Args: []v1alpha1.KProbeArg{
			v1alpha1.KProbeArg{
				Index: 7, /* whence */
			},
			v1alpha1.KProbeArg{
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
		fmt.Printf("Calling lseek...\n")
		unix.Seek(fd, 0, whence)
		unix.Seek(fd, 0, whence+1)
	}

	check := func(event *fgs.ProcessTracepoint) error {
		if len(event.Args) != 2 {
			return fmt.Errorf("unexpected number of arguments: %d", len(event.Args))
		}
		arg0, ok := event.Args[0].GetArg().(*fgs.KprobeArgument_SizeArg)
		if !ok {
			return fmt.Errorf("unexpected first arg: %s", event.Args[0])
		}
		xwhence := arg0.SizeArg
		if xwhence != whence_u {
			return fmt.Errorf("unexpected arg val. got:%d expecting:%d", xwhence, whence)
		}
		arg1, ok := event.Args[1].GetArg().(*fgs.KprobeArgument_SizeArg)
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
	tracepointConf := GenericTracepointConf{
		Subsystem: "syscalls",
		Event:     "sys_enter_write",
		Args: []v1alpha1.KProbeArg{
			v1alpha1.KProbeArg{
				Index: 5, /* fd */
			},
			v1alpha1.KProbeArg{
				Index:        6,     /* char *buf */
				SizeArgIndex: 7 + 1, /* count */

			},
		},
		Selectors: []v1alpha1.KProbeSelector{{
			MatchArgs: []v1alpha1.ArgSelector{{
				Index:    5,
				Operator: "eq",
				Values:   []string{"1"},
			}},
		}},
	}

	op := func() {
		syscall.Write(1, []byte("hello world"))
	}

	found := false
	check := func(event *fgs.ProcessTracepoint) error {
		if event.Subsys != "syscalls" {
			return fmt.Errorf("Unexpected subsys: %s", event.Subsys)
		}
		if event.Event != "sys_enter_write" {
			return fmt.Errorf("Unexpected subsys: %s", event.Event)
		}
		if len(event.Args) != 2 {
			return fmt.Errorf("Expecting single argument, but got %d", len(event.Args))
		}
		arg1_, ok := event.Args[1].GetArg().(*fgs.KprobeArgument_BytesArg)
		if !ok {
			return fmt.Errorf("Unexpected arg: %v", event.Args[1].GetArg())
		}
		arg1 := string(arg1_.BytesArg)
		if arg1 == "hello world" {
			found = true
		}
		return nil
	}

	doTestGenericTracepointPidFilter(t, tracepointConf, op, check)
	if !found {
		t.Logf("expected string not found")
		t.Fail()
	}
}
