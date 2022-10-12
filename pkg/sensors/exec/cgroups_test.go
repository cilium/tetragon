// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package exec

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/tetragon/pkg/api/ops"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/cgroups"
	grpcexec "github.com/cilium/tetragon/pkg/grpc/exec"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/base"
	testsensor "github.com/cilium/tetragon/pkg/sensors/test"
	"github.com/cilium/tetragon/pkg/testutils"
	"github.com/cilium/tetragon/pkg/testutils/perfring"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

const (
	defaultTimeout = 30 * time.Second

	tetragonCgrpRoot = "tetragon-tests"
)

func registerSensors(loaded []*sensors.Sensor) {
	for _, s := range loaded {
		sensors.RegisterSensorAtInit(s)
	}
}

func enableSensors(ctx context.Context, smanager *sensors.Manager, loaded []*sensors.Sensor) error {
	for _, s := range loaded {
		if err := smanager.EnableSensor(ctx, s.Name); err != nil {
			return err
		}
	}

	return nil
}

func disableSensors(ctx context.Context, smanager *sensors.Manager, loaded []*sensors.Sensor) error {
	for _, s := range loaded {
		if err := smanager.DisableSensor(ctx, s.Name); err != nil {
			return err
		}
	}

	return nil
}

func cgroupMkdir(t *testing.T, cgroupfsPath string, hierarchy string, dir string) error {
	path := filepath.Join(cgroupfsPath, hierarchy, dir)
	err := os.MkdirAll(path, 0755)
	if err != nil {
		t.Logf("test failed to create cgroup directory '%s': %v", path, err)
	} else {
		t.Logf("test created cgroup directory '%s' with success", path)
	}
	return err
}

func cgroupRmdir(t *testing.T, cgroupfsPath string, hierarchy string, dir string) error {
	path := filepath.Join(cgroupfsPath, hierarchy, dir)
	err := os.RemoveAll(path)
	if err != nil {
		t.Logf("test failed to clean cgroup directory '%s': %v", path, err)
	} else {
		t.Logf("test cleaned cgroup directory '%s' with success", path)
	}
	return err
}

// Test loading bpf cgroups programs
func TestLoadCgroupsPrograms(t *testing.T) {
	testutils.CaptureLog(t, logger.GetLogger().(*logrus.Logger))
	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	option.Config.HubbleLib = tus.Conf().TetragonLib
	option.Config.Verbosity = 5
	tus.LoadSensor(ctx, t, base.GetInitialSensor())
	tus.LoadSensor(ctx, t, testsensor.GetTestSensor())
	tus.LoadSensor(ctx, t, testsensor.GetCgroupSensor())
}

// Test `tg_conf_map` BPF map that it can hold runtime configuration
func TestTgRuntimeConf(t *testing.T) {
	testutils.CaptureLog(t, logger.GetLogger().(*logrus.Logger))
	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	option.Config.HubbleLib = tus.Conf().TetragonLib
	option.Config.Verbosity = 5

	_, err := observer.GetDefaultObserver(t, ctx, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}

	val, err := testutils.GetTgRuntimeConf()
	assert.NoError(t, err)

	assert.NotZero(t, val.NSPID)
	assert.NotZero(t, val.TgCgrpId)
	assert.NotZero(t, val.Mode)
	assert.NotZero(t, val.CgrpFsMagic)

	mapDir := bpf.MapPrefixPath()
	err = testutils.UpdateTgRuntimeConf(mapDir, val)
	assert.NoError(t, err)

	ret, err := testutils.ReadTgRuntimeConf(mapDir)
	assert.NoError(t, err)

	assert.EqualValues(t, ret, val)
}

// Test we do not receive any cgroup events from BPF side
func TestCgroupNoEvents(t *testing.T) {
	testutils.CaptureLog(t, logger.GetLogger().(*logrus.Logger))
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	option.Config.HubbleLib = tus.Conf().TetragonLib
	option.Config.Verbosity = 5

	_, err := observer.GetDefaultObserver(t, ctx, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}

	loadedSensors := []*sensors.Sensor{
		testsensor.GetTestSensor(),
		testsensor.GetCgroupSensor(),
	}

	registerSensors(loadedSensors)

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

	err = enableSensors(ctx, smanager, loadedSensors)
	if err != nil {
		t.Fatalf("enableSensors error: %s", err)
	}

	defer func() {
		disableSensors(ctx, smanager, loadedSensors)
		if err != nil {
			fmt.Printf("disableSensor failed: %s\n", err)
		}
	}()

	val, err := testutils.GetTgRuntimeConf()
	assert.NoError(t, err)

	// Set Log Level to trace so we receive BPF events
	val.LogLevel = uint32(logrus.TraceLevel)

	err = testutils.UpdateTgRuntimeConf(mapDir, val)
	assert.NoError(t, err)

	cgroupFSPath := cgroups.GetCgroupFSPath()
	assert.NotEmpty(t, cgroupFSPath)

	// Do not use random names so we can predict if directory
	// failed to be removed by previous tests...
	dir := fmt.Sprintf("%s/%s", tetragonCgrpRoot, t.Name())
	cgroupMode := cgroups.GetCgroupMode()
	assert.NotZero(t, uint32(cgroupMode))

	t.Logf("Test %s is running in '%s'", t.Name(), cgroupMode.String())
	hierarchy := ""
	if cgroupMode != cgroups.CGROUP_UNIFIED {
		// In cgroupv1 tracking
		hierarchy = cgroups.GetCgrpControllerName()
	}

	cgroupRmdir(t, cgroupFSPath, hierarchy, tetragonCgrpRoot)

	finalpath := filepath.Join(cgroupFSPath, hierarchy, dir)
	_, err = os.Stat(finalpath)
	if err == nil {
		t.Fatalf("Test %s failed cgroup test hierarchy should not exist '%s'", t.Name(), finalpath)
	}

	defer cgroupRmdir(t, cgroupFSPath, hierarchy, dir)
	trigger := func() {
		err = cgroupMkdir(t, cgroupFSPath, hierarchy, dir)
		assert.NoError(t, err)
	}

	events := perfring.RunTestEvents(t, ctx, trigger)
	for _, ev := range events {
		if msg, ok := ev.(*grpcexec.MsgCgroupEventUnix); ok {
			if msg.Common.Op == ops.MSG_OP_CGROUP {
				op := ops.CgroupOpCode(msg.CgrpOp)
				t.Fatalf("Test failed received a cgroup.event=%s", op)
			}
		}
	}
}

// Test Tetragon if it can discover cgroup configuration by using the
// cgroup_attach_task BPF tracepoint
func TestTetragonCgroupDiscovery(t *testing.T) {
	testutils.CaptureLog(t, logger.GetLogger().(*logrus.Logger))
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	option.Config.HubbleLib = tus.Conf().TetragonLib
	option.Config.Verbosity = 5

	obs, err := observer.GetDefaultObserver(t, ctx, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}

	loadedSensors := []*sensors.Sensor{
		testsensor.GetTestSensor(),
		testsensor.GetCgroupSensor(),
	}

	registerSensors(loadedSensors)

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

	err = enableSensors(ctx, smanager, loadedSensors)
	if err != nil {
		t.Fatalf("enableSensors error: %s", err)
	}

	defer func() {
		disableSensors(ctx, smanager, loadedSensors)
		if err != nil {
			fmt.Printf("disableSensor failed: %s\n", err)
		}
	}()

	trigger := func() {
		err = obs.UpdateRuntimeConf(mapDir)
		if err != nil {
			t.Fatalf("UpdateRuntimeConf() failed with: %v", err)
		}

		err = obs.ProbeTetragonCgroups()
		if err != nil {
			t.Fatalf("ProbeTetragonCgroups() failed with: %v", err)
		}
	}

	events := perfring.RunTestEvents(t, ctx, trigger)
	for _, ev := range events {
		if msg, ok := ev.(*grpcexec.MsgCgroupEventUnix); ok {
			if msg.Common.Op == ops.MSG_OP_CGROUP {
				op := ops.CgroupOpCode(msg.CgrpOp)
				st := ops.CgroupState(msg.CgrpData.State).String()
				if op == ops.MSG_OP_CGROUP_ATTACH_TASK {
					t.Logf("Test received  cgroup.event=%s  cgroup.state=%s  cgroup.IDTracker=%d  cgroup.id=%d  cgroup.level=%d",
						op.String(),
						st,
						msg.CgrpidTracker,
						msg.Cgrpid,
						msg.CgrpData.Level)
					assert.NotZero(t, msg.PID)
					assert.NotZero(t, msg.CgrpidTracker)
					assert.NotZero(t, msg.Cgrpid)
					assert.Equal(t, uint32(ops.CGROUP_RUNNING), msg.CgrpData.State)
					assert.NotZero(t, msg.CgrpData.Level)
					assert.NotEmpty(t, cgroups.CgroupNameFromCStr(msg.CgrpData.Name[:processapi.CGROUP_NAME_LENGTH]))
					assert.NotEmpty(t, cgroups.CgroupNameFromCStr(msg.Path[:processapi.CGROUP_PATH_LENGTH]))
					return
				} else {
					t.Fatalf("Test failed expecting a cgroup.event=%s  received cgroup.event=%s",
						ops.MSG_OP_CGROUP_ATTACH_TASK, op)
				}
			}
		}
	}

	t.Fatalf("Test failed we did not receive a cgroup event")
}
