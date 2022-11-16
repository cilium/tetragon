// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package exec

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/tetragon/pkg/api/ops"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/cgroups"
	grpcexec "github.com/cilium/tetragon/pkg/grpc/exec"
	"github.com/cilium/tetragon/pkg/mountinfo"
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
	"github.com/stretchr/testify/require"
)

type cgroupHierarchy struct {
	path     string
	tracking bool // Cgroup is being used as a tracking entity
	added    bool
	removed  bool
	cleanup  func(t *testing.T, root, name, path string)
}

type cgroupController struct {
	name    string // Controller name
	mounted bool   // Will be set if to true if mounted
	used    bool   // Will be set to true if controller is set and active
	cleanup func(t *testing.T, mountPoint string)
}

const (
	defaultTimeout = 30 * time.Second

	// Cgroup root directory for tests under /sys/fs/cgroup/...
	tetragonCgrpRoot = "tetragon-tests"

	invalidValue = ^uint32(0)
)

var (
	loadedSensors = []*sensors.Sensor{
		testsensor.GetTestSensor(),
		testsensor.GetCgroupSensor(),
	}

	defaultKubeCgroupHierarchy = []cgroupHierarchy{
		{"tetragon-tests-39d631b6f0fbc4e261c7a0ee636cf434-defaultKubeCgroupHierarchy-system.slice", true, false, false, nil},
		{"kubelet.slice", true, false, false, nil},
		{"kubelet-kubepods.slice", true, false, false, nil},
		{"kubelet-kubepods-besteffort.slice", true, false, false, nil},
		{"kubelet-kubepods-besteffort-pod2edf54f8_6911_449f_9abe_3d468a770d6b.slice", true, false, false, nil},
		{"cri-containerd-02de72688d6bb0908d279bbbb05ffa9d7e0b2ae17a8bf23683a33cc1349e55aa.scope", true, false, false, nil},
		{"nested-below-container-tracking-level+1", false, false, false, nil},
		{"nested-below-container-tracking-level+2", false, false, false, nil},
	}

	cgroupv1Controllers = []cgroupController{
		{"cpuset", false, false, nil},
		{"blkio", false, false, nil},
		{"memory", false, false, nil},
		{"pids", false, false, nil},
		{"devices", false, false, nil},
	}
)

func init() {
	tus.RegisterSensorsAtInit(loadedSensors)
}

func logDefaultCgroupConfig(t *testing.T) {
	path := cgroups.GetCgroupFSPath()
	magic := cgroups.GetCgroupFSMagic()
	cgroupMode := cgroups.GetCgroupMode()
	mode := cgroups.GetDeploymentMode()

	t.Logf("Test %s default configuration: deployment.mode='%s'  cgroup.path='%s'  cgroup.mode='%s'  cgroup.magic='%s'",
		t.Name(), cgroups.DeploymentCode(mode).String(),
		path, cgroups.CgroupModeCode(cgroupMode).String(),
		cgroups.CgroupFsMagicStr(magic))
}

func logTetragonConfig(t *testing.T, mapDir string) error {
	conf, err := testutils.ReadTgRuntimeConf(mapDir)
	if err != nil {
		return err
	}

	t.Logf("Test %s tetragon configuration: cgroup.magic=%s  logLevel=%d  cgroup.hierarchyID=%d  cgroup.subsysIdx=%d  cgroup.trackinglevel=%d  cgroup.ID=%d",
		t.Name(), cgroups.CgroupFsMagicStr(conf.CgrpFsMagic), conf.LogLevel, conf.TgCgrpHierarchy, conf.TgCgrpSubsysIdx, conf.TgCgrpLevel, conf.TgCgrpId)

	return nil
}

func logCgroupMountInfo(t *testing.T) error {
	mountInfos, err := mountinfo.GetMountInfo()
	if err != nil {
		return err
	}

	for _, mountInfo := range mountInfos {
		if strings.Contains(mountInfo.MountPoint, "cgroup") ||
			strings.Contains(mountInfo.FilesystemType, "cgroup") {
			t.Logf("Cgroup mount:%+v", mountInfo)
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

func mountCgroup(t *testing.T, root string, kind string, option string) (string, error) {
	err := os.MkdirAll(root, os.ModeDir)
	if err != nil {
		return "", err
	}

	err = syscall.Mount(root, root, kind, 0, option)
	if err != nil {
		return "", err
	}

	t.Logf("Mount %s  type=%s succeeded", root, kind)
	return root, nil
}

func umountCgroup(t *testing.T, root string) error {
	err := syscall.Unmount(root, 0)
	if err != nil {
		t.Logf("Failed to unmount %s: %v", root, err)
	} else {
		t.Logf("Unmount %s succeeded", root)
	}
	return err
}

func getCgroupEventOpAndPath(t *testing.T, msg *grpcexec.MsgCgroupEventUnix, cgroupHierarchy []cgroupHierarchy) (ops.CgroupOpCode, string) {
	if msg.Common.Op != ops.MSG_OP_CGROUP {
		return ops.CgroupOpCode(ops.MSG_OP_CGROUP_UNDEF), ""
	}

	cgrpPath := cgroups.CgroupNameFromCStr(msg.Path[:processapi.CGROUP_PATH_LENGTH])
	require.NotEmpty(t, cgrpPath)

	cgrpName := cgroups.CgroupNameFromCStr(msg.CgrpData.Name[:processapi.CGROUP_NAME_LENGTH])
	require.NotEmpty(t, cgrpName)
	require.Equal(t, cgrpName, filepath.Base(cgrpPath))

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

	// match only our target cgroup paths
	if strings.HasPrefix(cgrpPath, filepath.Join("/", cgroupHierarchy[0].path)) == false {
		return ops.CgroupOpCode(ops.MSG_OP_CGROUP_UNDEF), ""
	}

	require.NotZero(t, msg.PID)
	require.NotZero(t, msg.Cgrpid)
	require.NotZero(t, msg.CgrpidTracker)
	require.NotEqualValues(t, msg.CgrpData.State, ops.CGROUP_UNTRACKED)
	require.NotZero(t, msg.CgrpData.Level)

	return op, cgrpPath
}

func requireCgroupEventOpMkdir(t *testing.T, msg *grpcexec.MsgCgroupEventUnix, cgrpMapPath string) {
	require.EqualValues(t, ops.CGROUP_NEW, msg.CgrpData.State)

	looked, err := cgrouptrackmap.LookupTrackingCgroup(cgrpMapPath, msg.CgrpidTracker)
	assert.NoError(t, err)
	if looked == nil {
		t.Fatalf("Failed to find tracking cgroupID=%d in bpf-map=%s", msg.CgrpidTracker, cgrpMapPath)
	}
	require.EqualValues(t, msg.CgrpData.Level, looked.Level)
	require.EqualValues(t, msg.CgrpData.Name, looked.Name)
}

func requireCgroupEventOpRmdir(t *testing.T, msg *grpcexec.MsgCgroupEventUnix, cgrpMapPath string) {
	looked, err := cgrouptrackmap.LookupTrackingCgroup(cgrpMapPath, msg.CgrpidTracker)
	assert.Error(t, err)
	if looked != nil {
		t.Fatalf("Failed found tracking cgroup with cgroupID=%d in bpf-map=%s", msg.CgrpidTracker, cgrpMapPath)
	}
}

func assertCgroupDirTracking(t *testing.T, cgroupHierarchy []cgroupHierarchy) {
	for i, c := range cgroupHierarchy {
		if c.tracking == true {
			assert.Equalf(t, true, c.added,
				"failed at cgroupHierarchy[%d].path=%s should be tracked and added into bpf-map", i, c.path)
			assert.Equalf(t, true, c.removed,
				"failed at cgroupHierarchy[%d].path=%s should be tracked and removed from bpf-map", i, c.path)
		} else {
			assert.Equalf(t, false, c.added,
				"failed at cgroupHierarchy[%d].path=%s should not be tracked nor added into bpf-map", i, c.path)
			assert.Equalf(t, false, c.removed,
				"failed at cgroupHierarchy[%d].path=%s should not be tracked nor added/removed from bpf-map", i, c.path)
		}
	}
}

// Asserts cgroupv1 hierarchies events
func assertCgroupv1Events(ctx context.Context, t *testing.T, selectedController string, cgroupHierarchiesMap map[string][]cgroupHierarchy, trackedLevel uint32, trigger func()) {
	cgrpMapPath := filepath.Join(bpf.MapPrefixPath(), testsensor.GetCgroupsTrackingMap().Name)
	events := perfring.RunTestEvents(t, ctx, trigger)
	for _, ev := range events {
		if msg, ok := ev.(*grpcexec.MsgCgroupEventUnix); ok {
			if msg.Common.Op == ops.MSG_OP_CGROUP {
				cgrpPath := ""
				op := ops.MSG_OP_CGROUP_UNDEF
				controller := ""
				// iterate over all cgroup controllers and hierarchies and try to validate
				for hierarchy, cgroupHierarchy := range cgroupHierarchiesMap {
					op, cgrpPath = getCgroupEventOpAndPath(t, msg, cgroupHierarchy)
					if cgrpPath != "" {
						controller = hierarchy
						break
					}
				}
				// match only our target cgroup paths
				if cgrpPath == "" {
					continue
				}

				require.NotEmpty(t, controller)

				// We passed a faked selected Controller so we should not update it
				// inside cgroupHierarchiesMap
				if controller != selectedController {
					continue
				}

				cgrpName := filepath.Base(cgrpPath)
				require.Equal(t, cgrpName, cgroups.CgroupNameFromCStr(msg.CgrpData.Name[:processapi.CGROUP_NAME_LENGTH]))

				if msg.CgrpData.Level > trackedLevel {
					t.Fatalf("Error received cgroup event below tracked cgroup hierarchy, level:%d , path:%s",
						msg.CgrpData.Level, cgrpPath)
				}
				switch op {
				case ops.MSG_OP_CGROUP_MKDIR:
					require.EqualValues(t, ops.CGROUP_NEW, msg.CgrpData.State)
					require.EqualValues(t, cgroupHierarchiesMap[controller][msg.CgrpData.Level-1].path, cgrpName)

					requireCgroupEventOpMkdir(t, msg, cgrpMapPath)
					cgroupHierarchiesMap[controller][msg.CgrpData.Level-1].added = true
				case ops.MSG_OP_CGROUP_RMDIR:
					require.EqualValues(t, cgroupHierarchiesMap[controller][msg.CgrpData.Level-1].path, cgrpName)
					requireCgroupEventOpRmdir(t, msg, cgrpMapPath)
					cgroupHierarchiesMap[controller][msg.CgrpData.Level-1].removed = true
				}
			}
		}
	}
}

func assertCgroupv2Events(ctx context.Context, t *testing.T, cgroupHierarchy []cgroupHierarchy, trackedLevel uint32, trigger func()) {
	cgrpMapPath := filepath.Join(bpf.MapPrefixPath(), testsensor.GetCgroupsTrackingMap().Name)
	events := perfring.RunTestEvents(t, ctx, trigger)
	for _, ev := range events {
		if msg, ok := ev.(*grpcexec.MsgCgroupEventUnix); ok {
			if msg.Common.Op == ops.MSG_OP_CGROUP {
				op, cgrpPath := getCgroupEventOpAndPath(t, msg, cgroupHierarchy)
				// match only our target cgroup paths
				if cgrpPath == "" {
					continue
				}
				cgrpName := filepath.Base(cgrpPath)
				require.Equal(t, cgrpName, cgroups.CgroupNameFromCStr(msg.CgrpData.Name[:processapi.CGROUP_NAME_LENGTH]))

				if msg.CgrpData.Level > trackedLevel {
					t.Fatalf("Error received cgroup event below tracked cgroup hierarchy, level:%d , path:%s",
						msg.CgrpData.Level, cgrpPath)
				}
				switch op {
				case ops.MSG_OP_CGROUP_MKDIR:
					require.EqualValues(t, ops.CGROUP_NEW, msg.CgrpData.State)
					require.EqualValues(t, cgroupHierarchy[msg.CgrpData.Level-1].path, cgrpName)

					requireCgroupEventOpMkdir(t, msg, cgrpMapPath)
					cgroupHierarchy[msg.CgrpData.Level-1].added = true
				case ops.MSG_OP_CGROUP_RMDIR:
					require.EqualValues(t, cgroupHierarchy[msg.CgrpData.Level-1].path, cgrpName)
					requireCgroupEventOpRmdir(t, msg, cgrpMapPath)
					cgroupHierarchy[msg.CgrpData.Level-1].removed = true
				}
			}
		}
	}
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

func setupTgRuntimeConf(t *testing.T, trackingCgrpLevel, logLevel, hierarchyId, subSysIdx uint32) {
	val, err := testutils.GetTgRuntimeConf()
	if err != nil {
		t.Fatalf("GetTgRuntimeConf() failed: %v", err)
	}

	if logLevel != invalidValue {
		val.LogLevel = logLevel
	}

	if trackingCgrpLevel != invalidValue {
		val.TgCgrpLevel = trackingCgrpLevel
	}

	if hierarchyId != invalidValue {
		val.TgCgrpHierarchy = hierarchyId
	}

	if subSysIdx != invalidValue {
		val.TgCgrpSubsysIdx = subSysIdx
	}

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
	t.Cleanup(func() {
		testManager.DisableSensors(ctx, t, loadedSensors)
	})

	// Set Cgroup Tracking level to Zero means no tracking and no
	// cgroup events, all bpf cgroups related programs have no effect
	trackingCgrpLevel := uint32(0)
	setupTgRuntimeConf(t, trackingCgrpLevel, uint32(logrus.TraceLevel), invalidValue, invalidValue)

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
	t.Cleanup(func() {
		testManager.DisableSensors(ctx, t, loadedSensors)
	})

	// Set Tracking level to 3 so we receive notifcations about
	// /sys/fs/cgroup/$1/$2/$3 all cgroups that are at level <=3
	trackingCgrpLevel := uint32(3)
	setupTgRuntimeConf(t, trackingCgrpLevel, uint32(logrus.TraceLevel), invalidValue, invalidValue)

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

func testCgroupv2HierarchyInHybrid(ctx context.Context, t *testing.T,
	cgroupRoot string, cgroupHierarchy []cgroupHierarchy, trackingCgrpLevel uint32,
	triggers []func()) {

	t.Logf("Test %s running in %s", t.Name(), cgroups.CgroupModeCode(cgroups.CGROUP_HYBRID).String())
	unifiedCgroup := "unified" // in Hybrid setup the unified cgroup is the cgroupv2 instance
	t.Logf("Test %s cgroup mount point: %s -> %s", t.Name(), filepath.Join(cgroups.GetCgroupFSPath(), unifiedCgroup), cgroupRoot)

	// Ensure that we do not have a test cgroup hierarchy since cgroupfs is shared
	sharedCgroupPath := filepath.Join(cgroups.GetCgroupFSPath(), unifiedCgroup, cgroupHierarchy[0].path)
	t.Logf("Test %s cleaning up cgroup: %s", t.Name(), sharedCgroupPath)

	/* Guard against accidental errors*/
	require.NotEqual(t, filepath.Clean(filepath.Join(cgroups.GetCgroupFSPath(), unifiedCgroup)), filepath.Clean(sharedCgroupPath))

	os.RemoveAll(sharedCgroupPath)
	_, err := os.Stat(sharedCgroupPath)
	require.Error(t, err)

	// Run tests on the unified cgroup hierarchy (cgroupv2) of the hybrid setup
	for _, trigger := range triggers {
		assertCgroupv2Events(ctx, t, cgroupHierarchy, trackingCgrpLevel, trigger)
	}
}

func testCgroupv1HierarchyInHybrid(ctx context.Context, t *testing.T,
	cgroupRoot string, usedController string, cgroupHierarchiesMap map[string][]cgroupHierarchy, trackingCgrpLevel uint32,
	triggers []func()) {

	t.Logf("Test %s running in %s", t.Name(), cgroups.CgroupModeCode(cgroups.CGROUP_HYBRID).String())

	for hierarchy, cgroupHierarchy := range cgroupHierarchiesMap {
		hierarchyPath := filepath.Join(cgroups.GetCgroupFSPath(), hierarchy)
		t.Logf("Test %s cgroup mount point: %s -> %s", t.Name(), hierarchyPath, filepath.Join(cgroupRoot, hierarchy))

		// Ensure that we do not have a test cgroup hierarchy since cgroupfs is shared
		sharedCgroupPath := filepath.Join(hierarchyPath, cgroupHierarchy[0].path)

		/* Guard against accidental errors*/
		require.NotEqual(t, filepath.Clean(hierarchyPath), filepath.Clean(sharedCgroupPath))

		t.Logf("Test %s cleaning up cgroup: %s", t.Name(), sharedCgroupPath)
		os.RemoveAll(sharedCgroupPath)
		_, err := os.Stat(sharedCgroupPath)
		require.Error(t, err)
	}

	for _, trigger := range triggers {
		assertCgroupv1Events(ctx, t, usedController, cgroupHierarchiesMap, trackingCgrpLevel, trigger)
	}
}

// Test Cgroupv2 tries to emulate k8s hierarchy without exec context
func testCgroupv2HierarchyInUnified(ctx context.Context, t *testing.T,
	cgroupRoot string, cgroupHierarchy []cgroupHierarchy, trackingCgrpLevel uint32,
	triggers []func()) {

	t.Logf("Test %s running in %s", t.Name(), cgroups.CgroupModeCode(cgroups.CGROUP_UNIFIED).String())
	t.Logf("Test %s cgroup mount point: %s -> %s", t.Name(), cgroups.GetCgroupFSPath(), cgroupRoot)

	// Ensure that we do not have a test cgroup hierarchy since cgroupfs is shared
	sharedCgroupPath := filepath.Join(cgroups.GetCgroupFSPath(), cgroupHierarchy[0].path)
	t.Logf("Test %s cleaning up cgroup: %s", t.Name(), sharedCgroupPath)

	/* Guard against accidental errors*/
	require.NotEqual(t, filepath.Clean(cgroups.GetCgroupFSPath()), filepath.Clean(sharedCgroupPath))

	os.RemoveAll(sharedCgroupPath)
	_, err := os.Stat(sharedCgroupPath)
	require.Error(t, err)

	// Run tests on the default cgroupv2 mount point
	for _, trigger := range triggers {
		assertCgroupv2Events(ctx, t, cgroupHierarchy, trackingCgrpLevel, trigger)
	}
}

// Test Cgroupv2 tries to emulate k8s hierarchy without exec context
// Works in systemd unified and hybrid mode according to parameter
func testCgroupv2K8sHierarchy(ctx context.Context, t *testing.T, mode cgroups.CgroupModeCode) {
	testManager := tus.StartTestSensorManager(ctx, t)
	observer.SensorManager = testManager.Manager

	testManager.EnableSensors(ctx, t, loadedSensors)
	t.Cleanup(func() {
		testManager.DisableSensors(ctx, t, loadedSensors)
	})

	// Probe full environment detection
	setupTgRuntimeConf(t, invalidValue, invalidValue, invalidValue, invalidValue)
	if mode != cgroups.CGROUP_HYBRID && mode != cgroups.CGROUP_UNIFIED {
		logDefaultCgroupConfig(t)
		t.Skipf("Skipping test %s as default cgroup mode is not Unified nor Hybrid mode (Cgroupv1 and Cgroupv2)", t.Name())
	}

	testDir := t.TempDir()
	cgroupRoot, err := mountCgroup(t, testDir, "cgroup2", "")
	if err != nil {
		t.Fatalf("mountCgroup() failed: %v", err)
	}

	t.Cleanup(func() {
		umountCgroup(t, cgroupRoot)
	})

	trackingCgrpLevel := uint32(0)
	for i, c := range defaultKubeCgroupHierarchy {
		if c.tracking == false {
			trackingCgrpLevel = uint32(i)
			break
		}
	}

	require.NotZero(t, trackingCgrpLevel)
	require.True(t, trackingCgrpLevel <= uint32(len(defaultKubeCgroupHierarchy)))

	// Setup unified cgroup tracking 0 as hierarchy ID
	setupTgRuntimeConf(t, trackingCgrpLevel, uint32(logrus.TraceLevel), 0, invalidValue)

	logDefaultCgroupConfig(t)
	logTetragonConfig(t, bpf.MapPrefixPath())
	err = logCgroupMountInfo(t)
	assert.NoError(t, err)

	kubeCgroupHierarchy := make([]cgroupHierarchy, 0)
	for i, c := range defaultKubeCgroupHierarchy {
		n := cgroupHierarchy{
			path: c.path,
		}
		if c.tracking == true && uint32(i) < trackingCgrpLevel {
			n.tracking = true
		} else {
			n.tracking = false
		}
		kubeCgroupHierarchy = append(kubeCgroupHierarchy, n)
	}

	triggerCgroupMkdir := func() {
		last := cgroupRoot
		for _, dir := range kubeCgroupHierarchy {
			err = cgroupMkdir(t, last, "", dir.path)
			if err != nil {
				t.Fatalf("Failed to create cgroup %s/%s", last, dir.path)
			}
			last = filepath.Join(last, dir.path)
		}
	}

	triggerCgroupRmdir := func() {
		err = cgroupRmdir(t, cgroupRoot, "", kubeCgroupHierarchy[0].path)
		assert.NoError(t, err)
		path := "/"
		for _, dir := range defaultKubeCgroupHierarchy {
			path = filepath.Join(path, dir.path)
		}

		for i := 0; i < len(kubeCgroupHierarchy); i++ {
			err := cgroupRmdir(t, cgroupRoot, "", path)
			if err != nil {
				t.Fatalf("Failed to remove cgroup %s/%s", cgroupRoot, path)
			}
			path = filepath.Dir(path)
		}
	}

	triggers := []func(){
		triggerCgroupMkdir, triggerCgroupRmdir,
	}

	t.Cleanup(func() {
		cgroupRmdir(t, cgroupRoot, "", kubeCgroupHierarchy[0].path)
	})

	if mode == cgroups.CGROUP_HYBRID {
		// This test will run in hybrid mode since systemd will mount first cgroup2
		testCgroupv2HierarchyInHybrid(ctx, t, cgroupRoot, kubeCgroupHierarchy,
			trackingCgrpLevel, triggers)
	} else if mode == cgroups.CGROUP_UNIFIED {
		testCgroupv2HierarchyInUnified(ctx, t, cgroupRoot, kubeCgroupHierarchy,
			trackingCgrpLevel, triggers)
	} else {
		t.Fatalf("Test %s unsupported Cgroup Mode", t.Name())
	}

	assertCgroupDirTracking(t, kubeCgroupHierarchy)
}

// Test Cgroupv2 tries to emulate k8s hierarchy without exec context
// Works in systemd Unified pure cgroupv2
func TestCgroupv2K8sHierarchyInUnified(t *testing.T) {
	testutils.CaptureLog(t, logger.GetLogger().(*logrus.Logger))
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	option.Config.HubbleLib = tus.Conf().TetragonLib
	option.Config.Verbosity = 5

	_, err := observer.GetDefaultObserver(t, ctx, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}

	// Probe full environment detection
	setupTgRuntimeConf(t, invalidValue, invalidValue, invalidValue, invalidValue)
	if cgroups.GetCgroupMode() != cgroups.CGROUP_UNIFIED {
		logDefaultCgroupConfig(t)
		t.Skipf("Skipping test %s as default cgroup mode is not Unified mode (Cgroupv2)", t.Name())
	}

	testCgroupv2K8sHierarchy(ctx, t, cgroups.CGROUP_UNIFIED)
}

// Test Cgroupv2 tries to emulate k8s hierarchy without exec context
// Works in systemd hybrid mode
func TestCgroupv2K8sHierarchyInHybrid(t *testing.T) {
	testutils.CaptureLog(t, logger.GetLogger().(*logrus.Logger))
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	option.Config.HubbleLib = tus.Conf().TetragonLib
	option.Config.Verbosity = 5

	_, err := observer.GetDefaultObserver(t, ctx, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}

	// Probe full environment detection
	setupTgRuntimeConf(t, invalidValue, invalidValue, invalidValue, invalidValue)
	if cgroups.GetCgroupMode() != cgroups.CGROUP_HYBRID {
		logDefaultCgroupConfig(t)
		t.Skipf("Skipping test %s as default cgroup mode is not Hybrid mode (Cgroupv1 and Cgroupv2)", t.Name())
	}

	testCgroupv2K8sHierarchy(ctx, t, cgroups.CGROUP_HYBRID)
}

func testCgroupv1K8sHierarchyInHybrid(t *testing.T, selectedController string) {
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
	t.Cleanup(func() {
		testManager.DisableSensors(ctx, t, loadedSensors)
	})

	// Probe full environment detection
	setupTgRuntimeConf(t, invalidValue, invalidValue, invalidValue, invalidValue)
	if cgroups.GetCgroupMode() != cgroups.CGROUP_HYBRID {
		logDefaultCgroupConfig(t)
		t.Skipf("Skipping test %s as default cgroup mode is not Hybrid mode (Cgroupv1 and Cgroupv2)", t.Name())
	}

	testDir := t.TempDir()
	cgroupRoot, err := mountCgroup(t, testDir, "tmpfs", "")
	if err != nil {
		t.Fatalf("mountCgroup() failed: %v", err)
	}

	t.Cleanup(func() {
		umountCgroup(t, cgroupRoot)
	})

	trackingCgrpLevel := uint32(0)
	for i, c := range defaultKubeCgroupHierarchy {
		if c.tracking == false {
			trackingCgrpLevel = uint32(i)
			break
		}
	}

	require.NotZero(t, trackingCgrpLevel)
	require.True(t, trackingCgrpLevel <= uint32(len(defaultKubeCgroupHierarchy)))

	// First setup default cgroup
	setupTgRuntimeConf(t, trackingCgrpLevel, uint32(logrus.TraceLevel), invalidValue, invalidValue)
	// Fetch which controller name we will use
	usedController := cgroups.GetCgrpControllerName()

	if selectedController != "" && selectedController != usedController {
		found := false
		// Let's reset to selected Controller
		usedController = selectedController
		for _, ctrl := range cgroups.CgroupControllers {
			if ctrl.Name == selectedController && ctrl.Active {
				setupTgRuntimeConf(t, trackingCgrpLevel, uint32(logrus.TraceLevel),
					ctrl.Id, ctrl.Idx)
				t.Logf("SetupTgRuntimeConf() with Cgroup Hierarchy ID=%d  and Index=%d", ctrl.Id, ctrl.Idx)
				found = true
			}
			// If selectedController we fallback to default controller
			// probably memory or pids
		}

		/* If not found falls back to default selected controller by
		 * the cgroups auto discovery.
		 */
		if !found {
			usedController = cgroups.GetCgrpControllerName()
		}
	}

	// Make sure that we do not have an empty controller and we always have one
	require.NotEmpty(t, usedController)

	controllers := append([]cgroupController(nil), cgroupv1Controllers...)
	kubeCgroupHierarchiesMap := make(map[string][]cgroupHierarchy, len(cgroupv1Controllers))

	// Ensure we unmount all cgroup mount points
	cleanupMounts := func() {
		for _, controller := range controllers {
			if controller.mounted == true && controller.cleanup != nil {
				hierarchy := filepath.Join(cgroupRoot, controller.name)
				controller.cleanup(t, hierarchy)
			}
		}
	}
	t.Cleanup(cleanupMounts)

	// Ensure we remove all hierarchies
	cleanupHierarchies := func() {
		for _, controller := range controllers {
			c, ok := kubeCgroupHierarchiesMap[controller.name]
			if ok && c[0].cleanup != nil {
				c[0].cleanup(t, cgroupRoot, controller.name, c[0].path)
			}
		}
	}
	t.Cleanup(cleanupHierarchies)

	mountedControllers := 0
	for i, controller := range controllers {
		hierarchy := filepath.Join(cgroupRoot, controller.name)
		err = os.MkdirAll(hierarchy, 0555)
		assert.NoError(t, err)
		_, err := mountCgroup(t, hierarchy, "cgroup", controller.name)
		if err != nil {
			t.Logf("mountCgroup() %s failed: %v ignoring", hierarchy, err)
		} else {
			controllers[i].mounted = true
			controllers[i].cleanup = func(t *testing.T, mountPoint string) {
				umountCgroup(t, mountPoint)
			}
			kubeCgroupHierarchiesMap[controller.name] = make([]cgroupHierarchy, 0)
			for i, c := range defaultKubeCgroupHierarchy {
				n := cgroupHierarchy{}
				if i == 0 {
					// Prefix path so we can match it later easily
					n.path = fmt.Sprintf("%s-%s", controller.name, c.path)
					n.cleanup = func(t *testing.T, rootCgroup, name, path string) {
						cgroupRmdir(t, rootCgroup, name, path)
					}
				} else {
					n.path = c.path
				}
				if controller.name == usedController && uint32(i) < trackingCgrpLevel {
					n.tracking = true
				} else {
					n.tracking = false // Controller was not used at all, hierarchy not to be tracked
				}
				kubeCgroupHierarchiesMap[controller.name] = append(kubeCgroupHierarchiesMap[controller.name], n)
			}
			mountedControllers++
		}
	}

	require.NotZero(t, mountedControllers)

	logDefaultCgroupConfig(t)
	logTetragonConfig(t, bpf.MapPrefixPath())
	err = logCgroupMountInfo(t)
	assert.NoError(t, err)

	triggerCgroupMkdir := func() {
		for hierarchy, cgroupHierarchy := range kubeCgroupHierarchiesMap {
			path := ""
			for _, dir := range cgroupHierarchy {
				path = filepath.Join(path, dir.path)
				err = cgroupMkdir(t, cgroupRoot, hierarchy, path)
				if err != nil {
					t.Fatalf("Failed to create cgroup %s/%s/%s", cgroupRoot, hierarchy, dir.path)
				}
			}
		}
	}

	triggerCgroupRmdir := func() {
		for hierarchy, cgroupHierarchy := range kubeCgroupHierarchiesMap {
			path := "/"
			for _, dir := range cgroupHierarchy {
				path = filepath.Join(path, dir.path)
			}

			for i := 0; i < len(cgroupHierarchy); i++ {
				err := cgroupRmdir(t, cgroupRoot, hierarchy, path)
				if err != nil {
					t.Fatalf("Failed to remove cgroup %s/%s/%s", cgroupRoot, hierarchy, path)
				}
				path = filepath.Dir(path)
			}
		}
	}

	triggers := []func(){
		triggerCgroupMkdir, triggerCgroupRmdir,
	}

	// Loop over all created cgroup hierarchies
	testCgroupv1HierarchyInHybrid(ctx, t, cgroupRoot, usedController, kubeCgroupHierarchiesMap,
		trackingCgrpLevel, triggers)

	for _, cgroupHierarchy := range kubeCgroupHierarchiesMap {
		assertCgroupDirTracking(t, cgroupHierarchy)
	}
}

// Test Cgroupv1 tries to emulate k8s hierarchy without exec context
// Works in systemd hybrid mode
// This test will select the best cgroup controller to use
func TestCgroupv1K8sHierarchyInHybridDefault(t *testing.T) {
	testCgroupv1K8sHierarchyInHybrid(t, "")
}

// This test will use the memory cgroup controller if available
func TestCgroupv1K8sHierarchyInHybridMemory(t *testing.T) {
	testCgroupv1K8sHierarchyInHybrid(t, "memory")
}

// This test will use the pids cgroup controller if available
func TestCgroupv1K8sHierarchyInHybridPids(t *testing.T) {
	testCgroupv1K8sHierarchyInHybrid(t, "pids")
}

// This test will use the cpuset cgroup controller if available
func TestCgroupv1K8sHierarchyInHybridCpuset(t *testing.T) {
	testCgroupv1K8sHierarchyInHybrid(t, "cpuset")
}

// This test will not use the blkio, it will fallback to the
// best cgroup controller if available
func TestCgroupv1K8sHierarchyInHybridBlkio(t *testing.T) {
	testCgroupv1K8sHierarchyInHybrid(t, "blkio")
}

// This test will not use the invalid cgroup controller, it will
// fallback to the best cgroup controller if available
func TestCgroupv1K8sHierarchyInHybridInvalid(t *testing.T) {
	testCgroupv1K8sHierarchyInHybrid(t, "invalid-cgroup-controller")
}
