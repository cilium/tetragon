// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package confmap

import (
	"fmt"
	"path/filepath"
	"time"
	"unsafe"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/cgroups"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/sensors/base"
	"github.com/sirupsen/logrus"
)

type TetragonConfKey struct {
	Key uint32
}

type TetragonConfValue struct {
	Mode               uint32 // Deployment mode
	LogLevel           uint32 // Tetragon log level
	PID                uint32 // Tetragon PID for debugging purpose
	NSPID              uint32 // Tetragon PID in namespace for debugging purpose
	TgCgrpHierarchy    uint32 // Tetragon Cgroup tracking hierarchy
	TgCgrpHierarchyIdx uint32 // Tracking Cgroup hierarchy idx at compile time
	TgCgrpLevel        uint32 // Tetragon cgroup level
	Pad                uint32
	TgCgrpId           uint64 // Tetragon cgroup ID
	CgrpFsMagic        uint64 // Cgroupv1 or cgroupv2
}

var (
	log = logger.GetLogger()
)

func (k *TetragonConfKey) String() string             { return fmt.Sprintf("key=%d", k.Key) }
func (k *TetragonConfKey) GetKeyPtr() unsafe.Pointer  { return unsafe.Pointer(k) }
func (k *TetragonConfKey) DeepCopyMapKey() bpf.MapKey { return &TetragonConfKey{k.Key} }

func (k *TetragonConfKey) NewValue() bpf.MapValue { return &TetragonConfValue{} }

func (v *TetragonConfValue) String() string {
	return fmt.Sprintf("value=%d %s", 0, "")
}
func (v *TetragonConfValue) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }
func (v *TetragonConfValue) DeepCopyMapValue() bpf.MapValue {
	return &TetragonConfValue{}
}

func UpdateTetragonConfMap(mapDir string, nspid int) error {
	configMap := base.GetTetragonConfMap()
	mapPath := filepath.Join(mapDir, configMap.Name)

	m, err := bpf.OpenMap(mapPath)
	for i := 0; err != nil; i++ {
		m, err = bpf.OpenMap(mapPath)
		if err != nil {
			time.Sleep(1 * time.Second)
		}
		if i > 4 {
			log.WithField("confmap-update", configMap.Name).WithError(err).Warn("Failed to update TetragonConf map")
			return err
		}
	}

	defer m.Close()

	// First let's detect cgroupfs magic
	cgroupFsMagic, err := cgroups.GetBpfCgroupFS()
	if err != nil {
		log.WithField("confmap-update", configMap.Name).WithError(err).Warnf("Detection of Cgroupfs version failed")
		log.WithField("confmap-update", configMap.Name).Warnf("Cgroupfs magic is unknown, advanced Cgroups tracking will be disabled")
		return nil
	}

	// This must be called before probing cgroup configurations
	err = cgroups.DiscoverSubSysIds()
	if err != nil {
		log.WithField("confmap-update", configMap.Name).WithError(err).Warnf("Detection of Cgroup SubSys Controllers failed")
		log.WithField("confmap-update", configMap.Name).Warnf("Cgroup SubSys IDs are unknown, advanced Cgroups tracking will be disabled")
		return nil
	}

	// Detect deployment mode
	deployMode, err := cgroups.DetectDeploymentMode()
	if err != nil {
		deployMode = cgroups.CGROUP_UNSET_VALUE
		log.WithField("confmap-update", configMap.Name).WithError(err).Warnf("Detection of deployment mode failed")
		log.WithField("confmap-update", configMap.Name).Warnf("Deployment mode is unknown, advanced Cgroups tracking will be disabled")
		return nil
	}

	k := &TetragonConfKey{Key: 0}
	v := &TetragonConfValue{
		Mode:               deployMode,
		LogLevel:           uint32(logger.GetLogLevel()),
		NSPID:              uint32(nspid),
		TgCgrpHierarchy:    cgroups.GetCgrpHierarchyID(),
		TgCgrpHierarchyIdx: cgroups.GetCgrpHierarchyIdx(),
		TgCgrpLevel:        0,
		Pad:                0,
		CgrpFsMagic:        cgroupFsMagic,
	}

	err = m.Update(k, v)
	if err != nil {
		log.WithField("confmap-update", configMap.Name).WithError(err).Warn("Failed to update TetragonConf map")
		return err
	}

	log.WithFields(logrus.Fields{
		"confmap-update":       configMap.Name,
		"DeploymentMode":       cgroups.DeploymentCode(deployMode).String(),
		"LogLevel":             logrus.Level(v.LogLevel).String(),
		"NSPID":                nspid,
		"CgroupHierarchyID":    v.TgCgrpHierarchy,
		"CgroupHierarchyIndex": v.TgCgrpHierarchyIdx,
		"CgroupFSMagic":        cgroups.CgroupFsMagicStr(v.CgrpFsMagic),
	}).Info("Updated TetragonConf map successfully")

	return nil
}
