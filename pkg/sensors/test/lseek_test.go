// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package test

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cilium/tetragon/pkg/bpf"
	ec "github.com/cilium/tetragon/pkg/eventchecker"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/sensors"
	_ "github.com/cilium/tetragon/pkg/sensors/exec"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

// This bpf_lseek is a simple BPF program used for tests

var (
	ObserverLseekTest = program.Builder(
		"bpf_lseek.o",
		"syscalls/sys_enter_lseek",
		"tracepoint/sys_enter_lseek",
		"test_lseek",
		"tracepoint",
	)

	selfBinary  string
	tetragonLib string
	cmdWaitTime time.Duration
)

const (
	testMapDir = "testObserver"
)

func init() {
	flag.StringVar(&tetragonLib, "bpf-lib", "../../../bpf/objs/", "hubble lib directory (location of btf file and bpf objs). Will be overridden by an TETRAGON_LIB env variable.")
	flag.DurationVar(&cmdWaitTime, "command-wait", 20000*time.Millisecond, "duration to wait for tetragon to gather logs from commands")

	bpf.SetMapPrefix(testMapDir)
}

func TestMain(m *testing.M) {
	flag.Parse()
	bpf.CheckOrMountFS("")
	bpf.CheckOrMountDebugFS()
	bpf.ConfigureResourceLimits()
	selfBinary = filepath.Base(os.Args[0])
	exitCode := m.Run()
	os.Exit(exitCode)
}

func TestSensorLseekLoad(t *testing.T) {
	if _, err := os.Stat("/sys/kernel/debug/tracing/events/syscalls"); os.IsNotExist(err) {
		t.Skip("cannot use syscall tracepoints (consider enabling CONFIG_FTRACE_SYSCALLS)")
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()

	checker := ec.NewSingleMultiResponseChecker(
		ec.NewTestEventChecker().End(),
	)

	obs, err := observer.GetDefaultObserver(t, tetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}
	progs := []*program.Program{ObserverLseekTest}
	maps := []*program.Map{}
	sensor := &sensors.Sensor{Name: "lseekTest", Progs: progs, Maps: maps}
	if err := sensor.FindPrograms(ctx); err != nil {
		t.Fatalf("ObserverFindProgs error: %s", err)
	}
	mapDir := bpf.MapPrefixPath()
	if err := sensor.Load(ctx, mapDir, mapDir, ""); err != nil {
		t.Fatalf("observerLoadSensor error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()
	unix.Seek(-1, 0, 4444)

	err = observer.JsonTestCheck(t, checker)
	assert.NoError(t, err)

	sensors.UnloadSensor(ctx, mapDir, mapDir, sensor)
}

func TestSensorLseekEnable(t *testing.T) {
	if _, err := os.Stat("/sys/kernel/debug/tracing/events/syscalls"); os.IsNotExist(err) {
		t.Skip("cannot use syscall tracepoints (consider enabling CONFIG_FTRACE_SYSCALLS)")
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()

	checker := ec.NewSingleMultiResponseChecker(
		ec.NewTestEventChecker().End(),
	)

	obs, err := observer.GetDefaultObserver(t, tetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}

	sensorName := "lseekTest"
	progs := []*program.Program{ObserverLseekTest}
	maps := []*program.Map{}
	sensor := &sensors.Sensor{Name: sensorName, Progs: progs, Maps: maps}
	sensors.RegisterSensorAtInit(sensor)

	mapDir := bpf.MapPrefixPath()
	smanager, err := sensors.StartSensorManager(mapDir, mapDir, "")
	if err != nil {
		t.Fatalf("startSensorController failed: %s", err)
	}
	observer.SensorManager = smanager
	defer func() {
		err := smanager.StopSensorManager(ctx)
		if err != nil {
			fmt.Printf("stopSensorController failed: %s\n", err)
		}
	}()

	if err := smanager.EnableSensor(ctx, sensorName); err != nil {
		t.Fatalf("EnableSensor error: %s", err)
	}

	defer func() {
		err := smanager.DisableSensor(ctx, sensorName)
		if err != nil {
			fmt.Printf("DisableSensor failed: %s\n", err)
		}
	}()

	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()
	unix.Seek(-1, 0, 4444)

	err = observer.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}
