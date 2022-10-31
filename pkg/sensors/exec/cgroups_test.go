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
	"github.com/cilium/tetragon/pkg/cgroups"
	grpcexec "github.com/cilium/tetragon/pkg/grpc/exec"
	"github.com/cilium/tetragon/pkg/sensors"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors/base"
	"github.com/cilium/tetragon/pkg/sensors/cgroup/cgrouptrackmap"
	testsensor "github.com/cilium/tetragon/pkg/sensors/test"
	"github.com/cilium/tetragon/pkg/testutils"
	"github.com/cilium/tetragon/pkg/testutils/perfring"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

const (
	defaultTimeout = 30 * time.Second

	// Cgroup root directory for tests under /sys/fs/cgroup/...
	tetragonCgrpRoot = "tetragon-tests"
)

var (
	loadedSensors = []*sensors.Sensor{
		testsensor.GetTestSensor(),
		testsensor.GetCgroupSensor(),
	}
)

func init() {
	tus.RegisterSensorsAtInit(loadedSensors)
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

func getTestCgroupDirAndHierarchy(t *testing.T) (string, string) {
	// Do not use random names so we can predict if directory
	// failed to be removed by previous tests...
	dir := fmt.Sprintf("/%s/%s", tetragonCgrpRoot, t.Name())
	cgroupMode := cgroups.GetCgroupMode()
	assert.NotZero(t, uint32(cgroupMode))

	t.Logf("Test %s is running in '%s'", t.Name(), cgroupMode.String())

	hierarchy := ""
	if cgroupMode != cgroups.CGROUP_UNIFIED {
		// In cgroupv1 tracking
		hierarchy = cgroups.GetCgrpControllerName()
	}

	return dir, hierarchy
}

func setupTgRuntimeConf(t *testing.T, trackingCgrpLevel uint32, logLevel uint32) {
	val, err := testutils.GetTgRuntimeConf()
	if err != nil {
		t.Fatalf("GetTgRuntimeConf() failed: %v", err)
	}

	val.LogLevel = logLevel
	val.TgCgrpLevel = trackingCgrpLevel

	mapDir := bpf.MapPrefixPath()
	err = testutils.UpdateTgRuntimeConf(mapDir, val)
	if err != nil {
		t.Fatalf("UpdateTgRuntimeConf() failed: %v", err)
	}
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
	assert.NotZero(t, val.CgrpFsMagic)

	mapDir := bpf.MapPrefixPath()
	err = testutils.UpdateTgRuntimeConf(mapDir, val)
	assert.NoError(t, err)

	ret, err := testutils.ReadTgRuntimeConf(mapDir)
	assert.NoError(t, err)

	assert.EqualValues(t, ret, val)

	assert.Equal(t, ret.TgCgrpHierarchy, cgroups.GetCgrpHierarchyID())
	assert.Equal(t, ret.TgCgrpSubsysIdx, cgroups.GetCgrpSubsystemIdx())
	assert.Equal(t, ret.LogLevel, uint32(logger.GetLogLevel()))
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

	testManager := tus.StartTestSensorManager(ctx, t)
	observer.SensorManager = testManager.Manager

	testManager.EnableSensors(ctx, t, loadedSensors)

	// Set Cgroup Tracking level to Zero means no tracking and no
	// cgroup events, all bpf cgroups related programs have no effect
	trackingCgrpLevel := uint32(0)
	setupTgRuntimeConf(t, trackingCgrpLevel, uint32(logrus.TraceLevel))

	cgroupFSPath := cgroups.GetCgroupFSPath()
	assert.NotEmpty(t, cgroupFSPath)

	dir, hierarchy := getTestCgroupDirAndHierarchy(t)
	cgroupRmdir(t, cgroupFSPath, hierarchy, tetragonCgrpRoot)

	finalpath := filepath.Join(cgroupFSPath, hierarchy, dir)
	_, err = os.Stat(finalpath)
	if err == nil {
		t.Fatalf("Test %s failed cgroup test hierarchy should not exist '%s'", t.Name(), finalpath)
	}

	t.Cleanup(func() {
		cgroupRmdir(t, cgroupFSPath, hierarchy, dir)
	})

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

// Ensure that we get cgroup_{mkdir|rmdir} events
func TestCgroupEventMkdirRmdir(t *testing.T) {
	testutils.CaptureLog(t, logger.GetLogger().(*logrus.Logger))
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	option.Config.HubbleLib = tus.Conf().TetragonLib
	option.Config.Verbosity = 5

	_, err := observer.GetDefaultObserver(t, ctx, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}

	testManager := tus.StartTestSensorManager(ctx, t)
	observer.SensorManager = testManager.Manager

	testManager.EnableSensors(ctx, t, loadedSensors)

	// Set Tracking level to 3 so we receive notifcations about
	// /sys/fs/cgroup/$1/$2/$3 all cgroups that are at level <=3
	trackingCgrpLevel := uint32(3)
	setupTgRuntimeConf(t, trackingCgrpLevel, uint32(logrus.TraceLevel))

	cgroupFSPath := cgroups.GetCgroupFSPath()
	assert.NotEmpty(t, cgroupFSPath)

	dir, hierarchy := getTestCgroupDirAndHierarchy(t)
	cgroupRmdir(t, cgroupFSPath, hierarchy, tetragonCgrpRoot)

	matchedPath := dir
	finalPath := filepath.Join(cgroupFSPath, hierarchy, dir)
	_, err = os.Stat(finalPath)
	if err == nil {
		t.Fatalf("Test %s failed cgroup test hierarchy should not exist '%s'", t.Name(), finalPath)
	}

	t.Cleanup(func() {
		cgroupRmdir(t, cgroupFSPath, hierarchy, dir)
	})

	trigger := func() {
		err = cgroupMkdir(t, cgroupFSPath, hierarchy, dir)
		assert.NoError(t, err)

		err = cgroupRmdir(t, cgroupFSPath, hierarchy, dir)
		assert.NoError(t, err)
	}

	mkdir := false
	rmdir := false
	cgrpMap := testsensor.GetCgroupsTrackingMap()
	cgrpMapPath := filepath.Join(bpf.MapPrefixPath(), cgrpMap.Name)
	cgrpTrackingId := uint64(0)
	events := perfring.RunTestEvents(t, ctx, trigger)
	for _, ev := range events {
		if msg, ok := ev.(*grpcexec.MsgCgroupEventUnix); ok {
			if msg.Common.Op == ops.MSG_OP_CGROUP {
				cgrpPath := cgroups.CgroupNameFromCStr(msg.Path[:processapi.CGROUP_PATH_LENGTH])
				op := ops.CgroupOpCode(msg.CgrpOp)
				st := ops.CgroupState(msg.CgrpData.State).String()
				logger.GetLogger().WithFields(logrus.Fields{
					"cgroup.event":     op.String(),
					"PID":              msg.PID,
					"NSPID":            msg.NSPID,
					"cgroup.IDTracker": msg.CgrpidTracker,
					"cgroup.ID":        msg.Cgrpid,
					"cgroup.state":     st,
					"cgroup.level":     msg.CgrpData.Level,
					"cgroup.path":      cgrpPath,
				}).Info("Received Cgroup event")

				assert.NotZero(t, msg.PID)
				assert.NotZero(t, msg.Cgrpid)
				assert.NotZero(t, msg.CgrpidTracker)
				assert.NotEqualValues(t, msg.CgrpData.State, ops.CGROUP_UNTRACKED)
				assert.NotZero(t, msg.CgrpData.Level)

				switch op {
				case ops.MSG_OP_CGROUP_MKDIR:
					assert.EqualValues(t, ops.CGROUP_NEW, msg.CgrpData.State)
					// Match only our test
					if cgrpPath == matchedPath {
						cgrpName := cgroups.CgroupNameFromCStr(msg.CgrpData.Name[:processapi.CGROUP_NAME_LENGTH])
						assert.EqualValues(t, t.Name(), cgrpName)

						mkdir = true
						cgrpTrackingId = msg.CgrpidTracker
					}
				case ops.MSG_OP_CGROUP_RMDIR:
					// Match only our test
					if cgrpPath == matchedPath {
						cgrpName := cgroups.CgroupNameFromCStr(msg.CgrpData.Name[:processapi.CGROUP_NAME_LENGTH])
						assert.EqualValues(t, t.Name(), cgrpName)
						rmdir = true
					}
				}
			}
		}
	}

	// Ensure that we received proper events
	assert.Equal(t, true, mkdir)
	assert.Equal(t, true, rmdir)
	assert.NotZero(t, true, cgrpTrackingId)

	// Should be removed from the tracking map
	_, err = cgrouptrackmap.LookupTrackingCgroup(cgrpMapPath, cgrpTrackingId)
	assert.Error(t, err)
}
