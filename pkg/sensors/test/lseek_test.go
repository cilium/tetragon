// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package test

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/sensors"
	_ "github.com/cilium/tetragon/pkg/sensors/exec"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

// This bpf_lseek is a simple BPF program used for tests

func TestMain(m *testing.M) {
	ec := tus.TestSensorsRun(m, "SensorTest")
	os.Exit(ec)
}

func TestSensorLseekLoad(t *testing.T) {
	if _, err := os.Stat("/sys/kernel/debug/tracing/events/syscalls"); os.IsNotExist(err) {
		t.Skip("cannot use syscall tracepoints (consider enabling CONFIG_FTRACE_SYSCALLS)")
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	checker := ec.NewUnorderedEventChecker(
		ec.NewTestChecker(),
	)

	obs, err := observer.GetDefaultObserver(t, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}
	sensor := GetTestSensor()
	tus.LoadSensor(ctx, t, sensor)
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()
	unix.Seek(BogusFd, 0, BogusWhenceVal)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestSensorLseekEnable(t *testing.T) {
	if _, err := os.Stat("/sys/kernel/debug/tracing/events/syscalls"); os.IsNotExist(err) {
		t.Skip("cannot use syscall tracepoints (consider enabling CONFIG_FTRACE_SYSCALLS)")
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	checker := ec.NewUnorderedEventChecker(
		ec.NewTestChecker(),
	)

	obs, err := observer.GetDefaultObserver(t, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}

	sensor := GetTestSensor()
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

	if err := smanager.EnableSensor(ctx, sensor.Name); err != nil {
		t.Fatalf("EnableSensor error: %s", err)
	}

	defer func() {
		err := smanager.DisableSensor(ctx, sensor.Name)
		if err != nil {
			fmt.Printf("DisableSensor failed: %s\n", err)
		}
	}()

	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()
	unix.Seek(BogusFd, 0, BogusWhenceVal)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}
