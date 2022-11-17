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
	LogLevel        uint32 `align:"loglevel"`           // Tetragon log level
	PID             uint32 `align:"pid"`                // Tetragon PID for debugging purpose
	NSPID           uint32 `align:"nspid"`              // Tetragon PID in namespace for debugging purpose
	TgCgrpHierarchy uint32 `align:"tg_cgrp_hierarchy"`  // Tetragon Cgroup tracking hierarchy ID
	TgCgrpSubsysIdx uint32 `align:"tg_cgrp_subsys_idx"` // Tracking Cgroup css idx at compile time
	TgCgrpLevel     uint32 `align:"tg_cgrp_level"`      // Tetragon cgroup level
	TgCgrpId        uint64 `align:"tg_cgrpid"`          // Tetragon cgroup ID
	CgrpFsMagic     uint64 `align:"cgrp_fs_magic"`      // Cgroupv1 or cgroupv2
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
	return &TetragonConfValue{
		LogLevel:        v.LogLevel,
		PID:             v.PID,
		NSPID:           v.NSPID,
		TgCgrpHierarchy: v.TgCgrpHierarchy,
		TgCgrpSubsysIdx: v.TgCgrpSubsysIdx,
		TgCgrpLevel:     v.TgCgrpLevel,
		TgCgrpId:        v.TgCgrpId,
		CgrpFsMagic:     v.CgrpFsMagic,
	}
}

// UpdateTgRuntimeConf() Gathers information about Tetragon runtime environment and
// update the TetragonConfMap that is the BPF `tg_conf_map`.
//
// It detects the CgroupFS magic, Cgroup runtime mode, discovers cgroup css's that
// registered during boot and propagated to all tasks inside their css_set, detects
// the deployment mode from kubernetes, containers, to standalone or systemd services.
// All discovered information will also be logged for debugging purpose.
//
// On failures it returns an error, and it default prints a warning that advanced
// Cgroups tracking will be disabled which will affect process association with
// kubernetes pods and containers.
//
// Important: this function does not take extra arguments as it should auto detect
// environment without any help. For testing use the specific variant that can be
// tuned with specific argument values.
func UpdateTgRuntimeConf(mapDir string, nspid int) error {
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
			log.WithField("confmap-update", configMap.Name).Warn("Update TetragonConf map failed, advanced Cgroups tracking will be disabled")
			return err
		}
	}

	defer m.Close()

	// First let's detect cgroupfs magic
	cgroupFsMagic, err := cgroups.DetectCgroupFSMagic()
	if err != nil {
		log.WithField("confmap-update", configMap.Name).WithError(err).Warnf("Detection of Cgroupfs version failed")
		log.WithField("confmap-update", configMap.Name).Warn("Cgroupfs magic is unknown, advanced Cgroups tracking will be disabled")
		return err
	}

	// This must be called before probing cgroup configurations
	err = cgroups.DiscoverSubSysIds()
	if err != nil {
		log.WithField("confmap-update", configMap.Name).WithError(err).Warnf("Detection of Cgroup Subsystem Controllers failed")
		log.WithField("confmap-update", configMap.Name).Warn("Cgroup Subsystems IDs are unknown, advanced Cgroups tracking will be disabled")
		return err
	}

	// Detect deployment mode
	deployMode, err := cgroups.DetectDeploymentMode()
	if err != nil {
		log.WithField("confmap-update", configMap.Name).WithError(err).Warnf("Detection of deployment mode failed")
		log.WithField("confmap-update", configMap.Name).Warn("Deployment mode is unknown, advanced Cgroups tracking will be disabled")
		return err
	}

	k := &TetragonConfKey{Key: 0}
	v := &TetragonConfValue{
		LogLevel:        uint32(logger.GetLogLevel()),
		TgCgrpHierarchy: cgroups.GetCgrpHierarchyID(),
		TgCgrpSubsysIdx: cgroups.GetCgrpSubsystemIdx(),
		NSPID:           uint32(nspid),
		CgrpFsMagic:     cgroupFsMagic,
	}

	err = m.Update(k, v)
	if err != nil {
		log.WithField("confmap-update", configMap.Name).WithError(err).Warn("Failed to update TetragonConf map")
		log.WithField("confmap-update", configMap.Name).Warn("Update TetragonConf map failed, advanced Cgroups tracking will be disabled")
		return err
	}

	log.WithFields(logrus.Fields{
		"confmap-update":                configMap.Name,
		"deployment.mode":               cgroups.DeploymentCode(deployMode).String(),
		"log.level":                     logrus.Level(v.LogLevel).String(),
		"cgroup.fs.magic":               cgroups.CgroupFsMagicStr(v.CgrpFsMagic),
		"cgroup.controller.name":        cgroups.GetCgrpControllerName(),
		"cgroup.controller.hierarchyID": v.TgCgrpHierarchy,
		"cgroup.controller.index":       v.TgCgrpSubsysIdx,
		"NSPID":                         nspid,
	}).Info("Updated TetragonConf map successfully")

	return nil
}

func ReadTgRuntimeConf(mapDir string) (*TetragonConfValue, error) {
	configMap := base.GetTetragonConfMap()
	mapPath := filepath.Join(mapDir, configMap.Name)

	m, err := bpf.OpenMap(mapPath)
	if err != nil {
		return nil, err
	}

	defer m.Close()

	k := &TetragonConfKey{Key: 0}
	v, err := m.Lookup(k)
	if err != nil {
		return nil, err
	}

	return v.DeepCopyMapValue().(*TetragonConfValue), nil
}
