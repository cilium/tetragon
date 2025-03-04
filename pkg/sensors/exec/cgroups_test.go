// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package exec

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/tetragon/pkg/kernels"

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
	"github.com/cilium/tetragon/pkg/sensors/cgroup/cgrouptrackmap"
	"github.com/cilium/tetragon/pkg/sensors/config/confmap"
	"github.com/cilium/tetragon/pkg/sensors/exec/procevents"
	testsensor "github.com/cilium/tetragon/pkg/sensors/test"
	"github.com/cilium/tetragon/pkg/testutils"
	tuo "github.com/cilium/tetragon/pkg/testutils/observer"
	"github.com/cilium/tetragon/pkg/testutils/perfring"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type cgroupHierarchy struct {
	path            string
	tracking        bool // Cgroup is being used as a tracking entity
	added           bool
	removed         bool
	matchExecCgrpID bool
	mkdirCgrpID     uint64
	execCgrpID      uint64
	expectedDocker  string
	actualDocker    string
	cleanup         func(t *testing.T, root, name, path string)
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
	defaultKubeCgroupHierarchy = []cgroupHierarchy{
		{"tetragon-tests-39d631b6f0fbc4e261c7a0ee636cf434-defaultKubeCgroupHierarchy-system.slice", true, false, false, false, 0, 0, "", "", nil},
		{"kubelet.slice", true, false, false, false, 0, 0, "", "", nil},
		{"kubelet-kubepods.slice", true, false, false, false, 0, 0, "", "", nil},
		{"kubelet-kubepods-besteffort.slice", true, false, false, false, 0, 0, "", "", nil},
		{"kubelet-kubepods-besteffort-pod2edf54f8_6911_449f_9abe_3d468a770d6b.slice", true, false, false, false, 0, 0, "", "", nil},
		{"cri-containerd-02de72688d6bb0908d279bbbb05ffa9d7e0b2ae17a8bf23683a33cc1349e55aa.scope", true, false, false, false, 0, 0, "yes", "", nil},
		{"nested-below-container-tracking-level+1", false, false, false, false, 0, 0, "", "", nil},
		{"nested-below-container-tracking-level+2", false, false, false, false, 0, 0, "", "", nil},
	}

	cgroupv1Controllers = []cgroupController{
		{"cpuset", false, false, nil},
		{"blkio", false, false, nil},
		{"memory", false, false, nil},
		{"pids", false, false, nil},
		{"devices", false, false, nil},
	}
)

func getLoadedSensors() []*sensors.Sensor {
	return []*sensors.Sensor{
		testsensor.GetTestSensor(),
		testsensor.GetCgroupSensor(),
	}
}

func getTrackingLevel(cgroupHierarchy []cgroupHierarchy) uint32 {
	level := 0
	for i, cgroup := range cgroupHierarchy {
		if cgroup.tracking == false {
			level = i
			break
		}
	}

	return uint32(level)
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
		t.Name(), cgroups.CgroupFsMagicStr(conf.CgrpFsMagic), conf.LogLevel, conf.TgCgrpHierarchy, conf.TgCgrpv1SubsysIdx, conf.TgCgrpLevel, conf.TgCgrpId)

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

// Mount all Cgroupv1 controllers
func mountCgroupv1Controllers(t *testing.T, cgroupRoot string, usedController string) ([]cgroupController, error) {
	mountedControllers := 0
	usedControllerMounted := false

	controllers := append([]cgroupController(nil), cgroupv1Controllers...)

	for i, controller := range controllers {
		hierarchy := filepath.Join(cgroupRoot, controller.name)
		err := os.MkdirAll(hierarchy, 0555)
		assert.NoError(t, err)
		_, err = mountCgroup(t, hierarchy, "cgroup", controller.name)
		if err != nil {
			t.Logf("mountCgroup() %s failed: %v", hierarchy, err)
		} else {
			controllers[i].mounted = true
			controllers[i].cleanup = func(t *testing.T, mountPoint string) {
				umountCgroup(t, mountPoint)
			}
			if controller.name == usedController {
				usedControllerMounted = true
			}
			mountedControllers++
		}
	}

	if mountedControllers == 0 {
		return nil, fmt.Errorf("failed to mount cgroupv1 controllers")
	}
	if usedControllerMounted == false {
		// cleanup now
		unmountCgroupv1Controllers(t, cgroupRoot, controllers)
		return nil, fmt.Errorf("failed to mount cgroupv1 %s controller", usedController)
	}

	return controllers, nil
}

func unmountCgroupv1Controllers(t *testing.T, cgroupRoot string, controllers []cgroupController) {
	for _, controller := range controllers {
		if controller.mounted == true && controller.cleanup != nil {
			hierarchy := filepath.Join(cgroupRoot, controller.name)
			controller.cleanup(t, hierarchy)
		}
	}
}

func prepareCgroupv1Hierarchies(controllers []cgroupController, usedController string, trackingCgrpLevel uint32) (map[string][]cgroupHierarchy, error) {
	kubeCgroupHierarchiesMap := make(map[string][]cgroupHierarchy, len(controllers))

	for _, controller := range controllers {
		if controller.mounted == false {
			continue
		}

		kubeCgroupHierarchiesMap[controller.name] = make([]cgroupHierarchy, 0)
		for i, c := range defaultKubeCgroupHierarchy {
			n := cgroupHierarchy{}
			if i == 0 {
				// Prefix path so we can match it later easily in the argv
				n.path = fmt.Sprintf("%s-%s", controller.name, c.path)
				n.cleanup = func(t *testing.T, rootCgroup, name, path string) {
					cgroupRmdir(t, rootCgroup, name, path)
				}
			} else {
				n.path = c.path
			}
			// We track only usedController, other controllers are mounted but
			// not tracked to emulate a production system.
			if controller.name == usedController {
				if uint32(i) < trackingCgrpLevel {
					n.tracking = true
				}
				// We are tracking this controller expect docker fields
				n.expectedDocker = c.expectedDocker
			} else {
				n.tracking = false // Controller was not used at all, hierarchy not to be tracked
			}
			kubeCgroupHierarchiesMap[controller.name] = append(kubeCgroupHierarchiesMap[controller.name], n)
		}
	}

	return kubeCgroupHierarchiesMap, nil
}

func cleanupCgroupv1Hierarchies(t *testing.T, cgroupRoot string, controllers []cgroupController, cgroupHierarchiesMap map[string][]cgroupHierarchy) {
	for _, controller := range controllers {
		c := &cgroupHierarchiesMap[controller.name][0]
		if c.cleanup != nil {
			c.cleanup(t, cgroupRoot, controller.name, c.path)
		}
	}
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
		"cgroup.event":       op.String(),
		"PID":                msg.PID,
		"NSPID":              msg.NSPID,
		"cgroup.IDTracker":   msg.CgrpidTracker,
		"cgroup.ID":          msg.Cgrpid,
		"cgroup.state":       st,
		"cgroup.hierarchyID": msg.CgrpData.HierarchyId,
		"cgroup.level":       msg.CgrpData.Level,
		"cgroup.path":        cgrpPath,
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

func assertCgroupDirTracking(t *testing.T, cgroupHierarchy []cgroupHierarchy, assertRmdir bool) {
	for i, c := range cgroupHierarchy {
		if c.tracking == true {
			assert.Equalf(t, true, c.added,
				"failed at cgroupHierarchy[%d].path=%s should be tracked and added into bpf-map", i, c.path)
			if assertRmdir {
				assert.Equalf(t, true, c.removed,
					"failed at cgroupHierarchy[%d].path=%s should be tracked and removed from bpf-map", i, c.path)
			}
		} else {
			assert.Equalf(t, false, c.added,
				"failed at cgroupHierarchy[%d].path=%s should not be tracked nor added into bpf-map", i, c.path)
			assert.Equalf(t, false, c.removed,
				"failed at cgroupHierarchy[%d].path=%s should not be tracked nor added/removed from bpf-map", i, c.path)
		}
	}
}

func assertCgroupExecIDsTracking(t *testing.T, cgroupHierarchy []cgroupHierarchy) {
	for i, c := range cgroupHierarchy {
		assert.Equalf(t, c.expectedDocker, c.actualDocker, "failed at cgroupHierarchy[%d].path=%s  expected Docker and Actual one do not match", i, c.path)
		if c.matchExecCgrpID {
			// We are expecting that cgrpid mkdir and execve match
			assert.Equalf(t, uint64(c.mkdirCgrpID), uint64(c.execCgrpID), "failed at cgroupHierarchy[%d].path=%s  mkdirCgroupID != execCgroupID (%d != %d)",
				i, c.path, c.mkdirCgrpID, c.execCgrpID)
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

					// Get cgroup id from path
					targetPath := filepath.Join(cgroups.GetCgroupFSPath(), controller, cgrpPath)
					id, err := cgroups.GetCgroupIdFromPath(targetPath)
					require.NoErrorf(t, err, "failed to get cgroup ID from path %s", targetPath)
					// Assert that received cgroup id from event is same as the id from the cgroup fs
					require.EqualValues(t, msg.CgrpidTracker, id)

					requireCgroupEventOpMkdir(t, msg, cgrpMapPath)
					cgroupHierarchiesMap[controller][msg.CgrpData.Level-1].added = true
					// Save the cgrpid of the cgroup_mkdir so we can match it later with cgrpid of execve
					cgroupHierarchiesMap[controller][msg.CgrpData.Level-1].mkdirCgrpID = msg.CgrpidTracker
				case ops.MSG_OP_CGROUP_RMDIR:
					require.EqualValues(t, cgroupHierarchiesMap[controller][msg.CgrpData.Level-1].path, cgrpName)
					requireCgroupEventOpRmdir(t, msg, cgrpMapPath)
					cgroupHierarchiesMap[controller][msg.CgrpData.Level-1].removed = true
				}
			}
		}
		if exec, ok := ev.(*grpcexec.MsgExecveEventUnix); ok {
			if strings.Contains(exec.Unix.Process.Filename, "printf") {
				args := strings.Split(exec.Unix.Process.Args, `\n`)
				argDir := args[0]
				for i, cgroup := range cgroupHierarchiesMap[selectedController] {
					// Ensure that argument matches the target cgroup directory of
					// the hierarchy we want
					if cgroup.path == argDir {
						// cgroup path match, let's save the cgrpid of the execve
						cgroupHierarchiesMap[selectedController][i].execCgrpID = exec.Unix.Msg.Kube.Cgrpid
						// save the received docker id of the execve
						cgroupHierarchiesMap[selectedController][i].actualDocker = exec.Unix.Kube.Docker
						// we had our match break
						break
					}
				}
			}
		}
	}
}

func assertCgroupv2Events(ctx context.Context, t *testing.T, cgroupRoot string, cgroupHierarchy []cgroupHierarchy, trackedLevel uint32, trigger func()) {
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

					// Get cgroup id from path
					targetPath := filepath.Join(cgroupRoot, cgrpPath)
					id, err := cgroups.GetCgroupIdFromPath(targetPath)
					require.NoErrorf(t, err, "failed to get cgroup ID from path %s", targetPath)
					require.NoError(t, err)
					// Assert that received cgroup id from event is same as the id from the cgroup fs
					require.EqualValues(t, msg.CgrpidTracker, id)

					requireCgroupEventOpMkdir(t, msg, cgrpMapPath)
					cgroupHierarchy[msg.CgrpData.Level-1].added = true
					// Save the cgrpid of the cgroup_mkdir so we can match it later with cgrpid of execve
					cgroupHierarchy[msg.CgrpData.Level-1].mkdirCgrpID = msg.CgrpidTracker
				case ops.MSG_OP_CGROUP_RMDIR:
					require.EqualValues(t, cgroupHierarchy[msg.CgrpData.Level-1].path, cgrpName)
					requireCgroupEventOpRmdir(t, msg, cgrpMapPath)
					cgroupHierarchy[msg.CgrpData.Level-1].removed = true
				}
			}
		}
		if exec, ok := ev.(*grpcexec.MsgExecveEventUnix); ok {
			if strings.Contains(exec.Unix.Process.Filename, "printf") {
				args := strings.Split(exec.Unix.Process.Args, `\n`)
				argDir := args[0]
				for i, cgroup := range cgroupHierarchy {
					// Ensure that argument matches the target cgroup directory of
					// the hierarchy we want
					if cgroup.path == argDir {
						// cgroup path match, let's save the cgrpid of the execve
						cgroupHierarchy[i].execCgrpID = exec.Unix.Msg.Kube.Cgrpid
						// save the received docker id of the execve
						cgroupHierarchy[i].actualDocker = exec.Unix.Kube.Docker
						// we had our match break
						break
					}
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

// Tries to change the cgroup controller to be used for testing
// Returns the name of controller to be used on success, empty on failures
func changeTestCgrpController(t *testing.T, trackingCgrpLevel, traceLevel uint32, selectedController string) string {
	// First ensure that we detect full environment
	_, err := testutils.GetTgRuntimeConf()
	require.NoError(t, err)

	for _, ctrl := range cgroups.CgroupControllers {
		if ctrl.Name == selectedController && ctrl.Active {
			setupTgRuntimeConf(t, trackingCgrpLevel, traceLevel, ctrl.Id, ctrl.Idx)
			t.Logf("SetupTgRuntimeConf() with cgroup.controller.name=%s  cgroup.controller.hierarchyID=%d  cgroup.controller.index=%d",
				ctrl.Name, ctrl.Id, ctrl.Idx)
			return ctrl.Name
		}
	}

	return ""
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
		val.TgCgrpv1SubsysIdx = subSysIdx
	}

	mapDir := bpf.MapPrefixPath()
	err = confmap.UpdateConfMap(mapDir, val)
	if err != nil {
		t.Fatalf("UpdateTgRuntimeConf() failed: %v", err)
	}
}

func setupObserver(t *testing.T) *tus.TestSensorManager {
	testManager := tuo.GetTestSensorManager(t)
	if err := observer.InitDataCache(1024); err != nil {
		t.Fatalf("failed to call observer.InitDataCache %s", err)
	}
	return testManager
}

// Test loading bpf cgroups programs
func TestLoadCgroupsPrograms(t *testing.T) {
	testutils.CaptureLog(t, logger.GetLogger().(*logrus.Logger))

	option.Config.HubbleLib = tus.Conf().TetragonLib
	option.Config.Verbosity = 5
	tus.LoadInitialSensor(t)
	tus.LoadSensor(t, testsensor.GetTestSensor())
	tus.LoadSensor(t, testsensor.GetCgroupSensor())
}

// Test `tg_conf_map` BPF map that it can hold runtime configuration
func TestTgRuntimeConf(t *testing.T) {
	testutils.CaptureLog(t, logger.GetLogger().(*logrus.Logger))

	option.Config.HubbleLib = tus.Conf().TetragonLib
	option.Config.Verbosity = 5

	tus.LoadInitialSensor(t)

	val, err := testutils.GetTgRuntimeConf()
	assert.NoError(t, err)

	assert.NotZero(t, val.NSPID)
	assert.NotZero(t, val.CgrpFsMagic)

	mapDir := bpf.MapPrefixPath()
	err = confmap.UpdateConfMap(mapDir, val)
	assert.NoError(t, err)

	ret, err := testutils.ReadTgRuntimeConf(mapDir)
	assert.NoError(t, err)

	assert.EqualValues(t, ret, val)

	assert.Equal(t, ret.TgCgrpHierarchy, cgroups.GetCgrpHierarchyID())
	assert.Equal(t, ret.TgCgrpv1SubsysIdx, cgroups.GetCgrpv1SubsystemIdx())
	assert.Equal(t, ret.LogLevel, uint32(logger.GetLogLevel()))
}

// Test we do not receive any cgroup events from BPF side
func TestCgroupNoEvents(t *testing.T) {
	testutils.CaptureLog(t, logger.GetLogger().(*logrus.Logger))
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	option.Config.HubbleLib = tus.Conf().TetragonLib
	option.Config.Verbosity = 5

	tus.LoadInitialSensor(t)

	testManager := setupObserver(t)

	testManager.AddAndEnableSensors(ctx, t, getLoadedSensors())

	// Set Cgroup Tracking level to Zero means no tracking and no
	// cgroup events, all bpf cgroups related programs have no effect
	trackingCgrpLevel := uint32(0)
	setupTgRuntimeConf(t, trackingCgrpLevel, uint32(logrus.TraceLevel), invalidValue, invalidValue)

	cgroupFSPath := cgroups.GetCgroupFSPath()
	assert.NotEmpty(t, cgroupFSPath)

	dir, hierarchy := getTestCgroupDirAndHierarchy(t)
	cgroupRmdir(t, cgroupFSPath, hierarchy, tetragonCgrpRoot)

	finalpath := filepath.Join(cgroupFSPath, hierarchy, dir)
	_, err := os.Stat(finalpath)
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

	tus.LoadInitialSensor(t)

	testManager := setupObserver(t)

	testManager.AddAndEnableSensors(ctx, t, getLoadedSensors())
	t.Cleanup(func() {
		testManager.DisableSensors(ctx, t, getLoadedSensors())
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
	_, err := os.Stat(finalPath)
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
		assertCgroupv2Events(ctx, t, filepath.Join(cgroups.GetCgroupFSPath(), unifiedCgroup), cgroupHierarchy, trackingCgrpLevel, trigger)
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
		assertCgroupv2Events(ctx, t, cgroups.GetCgroupFSPath(), cgroupHierarchy, trackingCgrpLevel, trigger)
	}
}

// Test Cgroupv2 tries to emulate k8s hierarchy without exec context
// Works in systemd unified and hybrid mode according to parameter
func testCgroupv2K8sHierarchy(ctx context.Context, t *testing.T, mode cgroups.CgroupModeCode, withExec bool) {
	testManager := setupObserver(t)

	testManager.AddAndEnableSensors(ctx, t, getLoadedSensors())
	t.Cleanup(func() {
		testManager.DisableSensors(ctx, t, getLoadedSensors())
	})

	_, err := testutils.GetTgRuntimeConf()
	require.NoError(t, err)
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

	trackingCgrpLevel := getTrackingLevel(defaultKubeCgroupHierarchy)
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
			n.expectedDocker = c.expectedDocker
		} else {
			n.tracking = false
		}
		kubeCgroupHierarchy = append(kubeCgroupHierarchy, n)
	}

	t.Cleanup(func() {
		cgroupRmdir(t, cgroupRoot, "", kubeCgroupHierarchy[0].path)
	})

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

	// Generate cgroup rmdir events
	triggerCgroupRmdir := func() {
		path := "/"
		for _, dir := range kubeCgroupHierarchy {
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

	// Exec the cgroup-migrate script that will create cgroups,
	// migrate processes, then performs an execve to gather
	// exec events.
	testCgroupMigrate := testutils.RepoRootPath("contrib/tester-progs/cgroup-migrate.bash")
	triggerCgroupExec := func() {
		path := cgroupRoot
		for i, dir := range kubeCgroupHierarchy {
			path = filepath.Join(path, dir.path)
			if dir.tracking == true {
				kubeCgroupHierarchy[i].matchExecCgrpID = true
			}
			/* We expect docker field here */
			if dir.expectedDocker == "yes" {
				docker, _ := procevents.LookupContainerId(dir.path, true, false)
				require.NotEmpty(t, docker)
				kubeCgroupHierarchy[i].expectedDocker = docker
			}
			var outb, errb bytes.Buffer
			cmd := exec.Command(testCgroupMigrate, "--mode", "cgroupv2", "--new", dir.path, path)
			cmd.Stdout = &outb
			cmd.Stderr = &errb
			t.Logf("Executing command: %v", cmd.String())
			err := cmd.Run()
			stderr := errb.String()
			if len(stderr) > 0 {
				t.Logf("\nstderr:\n%v", stderr)
			}
			if err != nil {
				t.Fatalf("Command failed: %s", err)
			}
			if len(outb.String()) > 0 {
				t.Logf("\nstdout:\n%v\n", outb.String())
			}
		}
	}

	triggersMkdirRmdir := []func(){
		triggerCgroupMkdir, triggerCgroupRmdir,
	}

	triggersExecIDs := []func(){
		triggerCgroupExec, triggerCgroupRmdir,
	}

	if withExec {
		testCgroupv2HierarchyInUnified(ctx, t, cgroupRoot, kubeCgroupHierarchy,
			trackingCgrpLevel, triggersExecIDs)
	} else {
		if mode == cgroups.CGROUP_HYBRID {
			// This test will run in hybrid mode since systemd will mount first cgroup2
			testCgroupv2HierarchyInHybrid(ctx, t, cgroupRoot, kubeCgroupHierarchy,
				trackingCgrpLevel, triggersMkdirRmdir)
		} else if mode == cgroups.CGROUP_UNIFIED {
			testCgroupv2HierarchyInUnified(ctx, t, cgroupRoot, kubeCgroupHierarchy,
				trackingCgrpLevel, triggersMkdirRmdir)
		} else {
			t.Fatalf("Test %s unsupported Cgroup Mode", t.Name())
		}
	}

	// dump final constructed values
	t.Logf("\ncgroupHierarchy=%+v\n", kubeCgroupHierarchy)

	// Match cgroup mkdir and rmdir events
	if !kernels.MinKernelVersion("5.0") && withExec {
		// For old kernels when a process is migrated to a cgroup, and after
		// it terminates, it may take longer to get cgroup rmdir events, in
		// this case skip cgroup rmdir assertion and avoid flaky tests
		assertCgroupDirTracking(t, kubeCgroupHierarchy, false)
	} else {
		assertCgroupDirTracking(t, kubeCgroupHierarchy, true)
	}

	// Match cgroup mkdir and execve cgroup info events
	if withExec {
		assertCgroupExecIDsTracking(t, kubeCgroupHierarchy)
	}
}

// Test Cgroupv2 tries to emulate k8s hierarchy without exec context
// Works in systemd Unified pure cgroupv2
func TestCgroupv2K8sHierarchyInUnified(t *testing.T) {
	testutils.CaptureLog(t, logger.GetLogger().(*logrus.Logger))
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	option.Config.HubbleLib = tus.Conf().TetragonLib
	option.Config.Verbosity = 5

	tus.LoadInitialSensor(t)

	// Probe full environment detection
	setupTgRuntimeConf(t, invalidValue, invalidValue, invalidValue, invalidValue)
	if cgroups.GetCgroupMode() != cgroups.CGROUP_UNIFIED {
		logDefaultCgroupConfig(t)
		t.Skipf("Skipping test %s as default cgroup mode is not Unified mode (Cgroupv2)", t.Name())
	}

	testCgroupv2K8sHierarchy(ctx, t, cgroups.CGROUP_UNIFIED, false)
}

// Test Cgroupv2 tries to emulate k8s hierarchy without exec context
// Works in systemd hybrid mode
func TestCgroupv2K8sHierarchyInHybrid(t *testing.T) {
	testutils.CaptureLog(t, logger.GetLogger().(*logrus.Logger))
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	option.Config.HubbleLib = tus.Conf().TetragonLib
	option.Config.Verbosity = 5

	tus.LoadInitialSensor(t)

	// Probe full environment detection
	setupTgRuntimeConf(t, invalidValue, invalidValue, invalidValue, invalidValue)
	if cgroups.GetCgroupMode() != cgroups.CGROUP_HYBRID {
		logDefaultCgroupConfig(t)
		t.Skipf("Skipping test %s as default cgroup mode is not Hybrid mode (Cgroupv1 and Cgroupv2)", t.Name())
	}

	testCgroupv2K8sHierarchy(ctx, t, cgroups.CGROUP_HYBRID, false)
}

func testCgroupv1K8sHierarchyInHybrid(t *testing.T, withExec bool, selectedController string) {
	testutils.CaptureLog(t, logger.GetLogger().(*logrus.Logger))
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	option.Config.HubbleLib = tus.Conf().TetragonLib
	option.Config.Verbosity = 5

	tus.LoadInitialSensor(t)

	testManager := setupObserver(t)

	testManager.AddAndEnableSensors(ctx, t, getLoadedSensors())

	// Probe full environment detection
	_, err := testutils.GetTgRuntimeConf()
	require.NoError(t, err)
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

	trackingCgrpLevel := getTrackingLevel(defaultKubeCgroupHierarchy)
	require.NotZero(t, trackingCgrpLevel)
	require.True(t, trackingCgrpLevel <= uint32(len(defaultKubeCgroupHierarchy)))

	// First setup default cgroup with our tracking level and trace level
	setupTgRuntimeConf(t, trackingCgrpLevel, uint32(logrus.TraceLevel), invalidValue, invalidValue)
	// Fetch default controller name that we will use
	usedController := cgroups.GetCgrpControllerName()

	// See if we should use another controller for testing
	if selectedController != usedController {
		usedController = changeTestCgrpController(t, trackingCgrpLevel, uint32(logrus.TraceLevel), selectedController)
		if selectedController == "memory" || selectedController == "pids" {
			// We should always succeed to use memory or pids controllers otherwise panic
			require.NotEmptyf(t, usedController, "failed to use the %s controller", selectedController)
		}
		if usedController == "" {
			// If it failed let's switch back to any default controller returned by the implementation
			usedController = cgroups.GetCgrpControllerName()
		}
	}

	// Make sure that we do not have an empty controller and we always have one
	require.NotEmpty(t, usedController)

	controllers, err := mountCgroupv1Controllers(t, cgroupRoot, usedController)
	require.NoError(t, err)
	// Ensure we cleanup All cgroupv1 mounts
	t.Cleanup(func() {
		unmountCgroupv1Controllers(t, cgroupRoot, controllers)
	})

	kubeCgroupHierarchiesMap, err := prepareCgroupv1Hierarchies(controllers, usedController, trackingCgrpLevel)
	require.NoError(t, err)
	// Ensure we remove all hierarchies
	t.Cleanup(func() {
		cleanupCgroupv1Hierarchies(t, cgroupRoot, controllers, kubeCgroupHierarchiesMap)
	})

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

	// Exec the cgroup-migrate script that will create cgroup of the usedController,
	// migrate processes to this usedController then performs an execve to gather
	// exec events.
	testCgroupMigrate := testutils.RepoRootPath("contrib/tester-progs/cgroup-migrate.bash")
	triggerCgroupExec := func() {
		path := filepath.Join(cgroupRoot, usedController)
		for i, dir := range kubeCgroupHierarchiesMap[usedController] {
			path = filepath.Join(path, dir.path)
			if dir.tracking == true {
				kubeCgroupHierarchiesMap[usedController][i].matchExecCgrpID = true
			}
			/* We expect docker field here, so let's properly set it */
			if dir.expectedDocker == "yes" {
				docker, _ := procevents.LookupContainerId(dir.path, true, false)
				require.NotEmpty(t, docker)
				kubeCgroupHierarchiesMap[usedController][i].expectedDocker = docker
			}
			var outb, errb bytes.Buffer
			cmd := exec.Command(testCgroupMigrate, "--mode", "cgroupv1", "--controller", usedController,
				"--new", dir.path, path)
			cmd.Stdout = &outb
			cmd.Stderr = &errb
			t.Logf("Executing command: %v", cmd.String())
			err := cmd.Run()
			stderr := errb.String()
			if len(stderr) > 0 {
				t.Logf("\nstderr:\n%v", stderr)
			}
			if err != nil {
				t.Fatalf("Command failed: %s", err)
			}
			if len(outb.String()) > 0 {
				t.Logf("\nstdout:\n%v\n", outb.String())
			}
		}
	}

	// Cleanup created cgroups by the cgroup-migrate script.
	triggerCgroupExecRmdir := func() {
		path := "/"
		for _, dir := range kubeCgroupHierarchiesMap[usedController] {
			path = filepath.Join(path, dir.path)
		}
		for i := 0; i < len(kubeCgroupHierarchiesMap[usedController]); i++ {
			err := cgroupRmdir(t, cgroupRoot, usedController, path)
			if err != nil {
				t.Fatalf("Failed to remove cgroup %s/%s/%s", cgroupRoot, usedController, path)
			}
			path = filepath.Dir(path)
		}
	}

	triggersMkdirRmdir := []func(){
		triggerCgroupMkdir, triggerCgroupRmdir,
	}

	triggersExecIDs := []func(){
		triggerCgroupExec, triggerCgroupExecRmdir,
	}

	if withExec {
		testCgroupv1HierarchyInHybrid(ctx, t, cgroupRoot, usedController, kubeCgroupHierarchiesMap,
			trackingCgrpLevel, triggersExecIDs)
	} else {
		testCgroupv1HierarchyInHybrid(ctx, t, cgroupRoot, usedController, kubeCgroupHierarchiesMap,
			trackingCgrpLevel, triggersMkdirRmdir)
	}

	// dump final constructed values
	for controller, cgroupHierarchy := range kubeCgroupHierarchiesMap {
		t.Logf("\nkubeCgroupHierarchiesMap[%s]=%+v\n", controller, cgroupHierarchy)
	}

	// Match cgroup mkdir and rmdir events
	for _, cgroupHierarchy := range kubeCgroupHierarchiesMap {
		assertCgroupDirTracking(t, cgroupHierarchy, true)
	}

	if withExec {
		// Match cgroup mkdir and execve cgroup info events
		for _, cgroupHierarchy := range kubeCgroupHierarchiesMap {
			assertCgroupExecIDsTracking(t, cgroupHierarchy)
		}
	}
}

// Test Cgroupv1 tries to emulate k8s hierarchy without exec context
// Works in systemd hybrid mode
// This test will select the best cgroup controller to use
func TestCgroupv1K8sHierarchyInHybridDefault(t *testing.T) {
	testCgroupv1K8sHierarchyInHybrid(t, false, "")
}

// This test will use the memory cgroup controller if available
func TestCgroupv1K8sHierarchyInHybridMemory(t *testing.T) {
	testCgroupv1K8sHierarchyInHybrid(t, false, "memory")
}

// This test will use the pids cgroup controller if available
func TestCgroupv1K8sHierarchyInHybridPids(t *testing.T) {
	testCgroupv1K8sHierarchyInHybrid(t, false, "pids")
}

// This test will use the cpuset cgroup controller if available
func TestCgroupv1K8sHierarchyInHybridCpuset(t *testing.T) {
	testCgroupv1K8sHierarchyInHybrid(t, false, "cpuset")
}

// This test will not use the blkio, it will fallback to the
// best cgroup controller if available
func TestCgroupv1K8sHierarchyInHybridBlkio(t *testing.T) {
	testCgroupv1K8sHierarchyInHybrid(t, false, "blkio")
}

// This test will not use the invalid cgroup controller, it will
// fallback to the best cgroup controller if available
func TestCgroupv1K8sHierarchyInHybridInvalid(t *testing.T) {
	testCgroupv1K8sHierarchyInHybrid(t, false, "invalid-cgroup-controller")
}

// Test Cgroupv1 tries to emulate k8s hierarchy without exec context
// Works in systemd hybrid mode
// This test will select the best cgroup controller to use
func TestCgroupv1ExecK8sHierarchyInHybridDefault(t *testing.T) {
	testCgroupv1K8sHierarchyInHybrid(t, true, "")
}

// This test will use the memory cgroup controller if available
func TestCgroupv1ExecK8sHierarchyInHybridMemory(t *testing.T) {
	testCgroupv1K8sHierarchyInHybrid(t, true, "memory")
}

// This test will use the pids cgroup controller if available
func TestCgroupv1ExecK8sHierarchyInHybridPids(t *testing.T) {
	testCgroupv1K8sHierarchyInHybrid(t, true, "pids")
}

// This test will not use the blkio, it will fallback to the
// best cgroup controller if available
func TestCgroupv1ExecK8sHierarchyInHybridBlkio(t *testing.T) {
	testCgroupv1K8sHierarchyInHybrid(t, true, "blkio")
}

// This test will not use the invalid cgroup controller, it will
// fallback to the best cgroup controller if available
func TestCgroupv1ExecK8sHierarchyInHybridInvalid(t *testing.T) {
	testCgroupv1K8sHierarchyInHybrid(t, true, "invalid-cgroup-controller")
}

// Test Cgroupv2 tries to emulate k8s hierarchy with exec context
// Works in systemd hybrid mode
func TestCgroupv2ExecK8sHierarchyInUnified(t *testing.T) {
	testutils.CaptureLog(t, logger.GetLogger().(*logrus.Logger))
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	option.Config.HubbleLib = tus.Conf().TetragonLib
	option.Config.Verbosity = 5

	tus.LoadInitialSensor(t)

	// Probe full environment detection
	_, err := testutils.GetTgRuntimeConf()
	require.NoError(t, err)
	// We support only unified mode as in hybrid mode, controllers
	// are part of the hybrid cgroupv1 hierarchy, the cgroupv2 of
	// the hybrid is only used by systemd to track launched services/processes
	if cgroups.GetCgroupMode() != cgroups.CGROUP_UNIFIED {
		logDefaultCgroupConfig(t)
		t.Skipf("Skipping test %s as default cgroup mode is not Unified mode", t.Name())
	}

	testCgroupv2K8sHierarchy(ctx, t, cgroups.CGROUP_UNIFIED, true)
}
