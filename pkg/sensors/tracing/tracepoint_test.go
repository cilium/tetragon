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

	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	lc "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker/matchers/listmatcher"
	smatcher "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/testutils"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"

	_ "github.com/cilium/tetragon/pkg/sensors/exec"
)

var (
	selfBinary   string
	tetragonLib  string
	cmdWaitTime  time.Duration
	verboseLevel int

	testMapPrefix = "testObserver"

	whenceBogusValue = 4444
)

func init() {
	flag.StringVar(&tetragonLib, "bpf-lib", "../../../bpf/objs/", "hubble lib directory (location of btf file and bpf objs). Will be overridden by an TETRAGON_LIB env variable.")
	flag.DurationVar(&cmdWaitTime, "command-wait", 20000*time.Millisecond, "duration to wait for tetragon to gather logs from commands")
	flag.IntVar(&verboseLevel, "verbosity-level", 0, "verbosity level of verbose mode. (Requires verbose mode to be enabled.)")
}

func TestMain(m *testing.M) {
	flag.Parse()
	bpf.CheckOrMountFS("")
	bpf.CheckOrMountDebugFS()
	bpf.ConfigureResourceLimits()
	bpf.SetMapPrefix(testMapPrefix)
	selfBinary = filepath.Base(os.Args[0])
	exitCode := m.Run()
	// NB: we currently seem to fail to remove the /sys/fs/bpf/testObserver
	// dir. Do so here, until we figure out a way to do it properly.
	os.RemoveAll(bpf.MapPrefixPath())
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
	obs, err := observer.GetDefaultObserver(t, tetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}

	sm := testutils.StartTestSensorManager(ctx, t)
	// create and add sensor
	sensor, err := createGenericTracepointSensor([]GenericTracepointConf{lseekConf})
	if err != nil {
		t.Fatalf("failed to create generic tracepoint sensor: %s", err)
	}
	sm.AddAndEnableSensor(ctx, t, sensor, "GtpLseekTest")

	tpChecker := ec.NewProcessTracepointChecker().
		WithSubsys(smatcher.Full("syscalls")).
		WithEvent(smatcher.Full("sys_enter_lseek")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithSizeArg(uint64(whenceBogusValue)),
				ec.NewKprobeArgumentChecker().WithSizeArg(18446744073709551615), // -1
			))
	checker := ec.NewUnorderedEventChecker(tpChecker)

	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()
	unix.Seek(-1, 0, whenceBogusValue)
	time.Sleep(1000 * time.Millisecond)
	err = observer.JsonTestCheck(t, checker)
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
	obs, err := observer.GetDefaultObserver(t, tetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}

	sm := testutils.StartTestSensorManager(ctx, t)
	// create and add sensor
	sensor, err := createGenericTracepointSensor([]GenericTracepointConf{conf})
	if err != nil {
		t.Fatalf("failed to create generic tracepoint sensor: %s", err)
	}
	sm.AddAndEnableSensor(ctx, t, sensor, "GtpLseekTest")

	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()
	selfOp()

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

	checker := ec.FnEventChecker{
		NextCheckFn:  nextCheck,
		FinalCheckFn: finalCheck,
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
