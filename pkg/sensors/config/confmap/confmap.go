// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package confmap

import (
	"fmt"
	"path"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/cgroups"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors/base"
	"github.com/cilium/tetragon/pkg/sensors/exec/config"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const (
	configMapName = "tg_conf_map"
)

type TetragonConfKey struct {
	Key uint32
}

type TetragonConfValue struct {
	LogLevel          uint32 `align:"loglevel"`             // Tetragon log level
	PID               uint32 `align:"pid"`                  // Tetragon PID for debugging purpose
	NSPID             uint32 `align:"nspid"`                // Tetragon PID in namespace for debugging purpose
	TgCgrpHierarchy   uint32 `align:"tg_cgrp_hierarchy"`    // Tetragon Cgroup tracking hierarchy ID
	TgCgrpv1SubsysIdx uint32 `align:"tg_cgrpv1_subsys_idx"` // Tracking Cgroupv1 css idx at compile time
	TgCgrpLevel       uint32 `align:"tg_cgrp_level"`        // Tetragon cgroup level
	TgCgrpId          uint64 `align:"tg_cgrpid"`            // Tetragon cgroup ID
	CgrpFsMagic       uint64 `align:"cgrp_fs_magic"`        // Cgroupv1 or cgroupv2
}

var (
	log = logger.GetLogger()
)

// confmapSpec returns the spec for the configuration map
func confmapSpec() (*ebpf.MapSpec, error) {
	objName := config.ExecObj()
	objPath := path.Join(option.Config.HubbleLib, objName)
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, fmt.Errorf("loading spec for %s failed: %w", objPath, err)
	}
	mapSpec, ok := spec.Maps[configMapName]
	if !ok {
		return nil, fmt.Errorf("%s not found in %s (%v)", configMapName, objPath, spec.Maps)
	}
	return mapSpec, nil
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
	// First let's detect cgroupfs magic
	cgroupFsMagic, err := cgroups.DetectCgroupFSMagic()
	if err != nil {
		log.WithField("confmap-update", configMapName).WithError(err).Warnf("Detection of Cgroupfs version failed")
		log.WithField("confmap-update", configMapName).Warn("Cgroupfs magic is unknown, advanced Cgroups tracking will be disabled")
		return err
	}

	// This must be called before probing cgroup configurations
	err = cgroups.DiscoverSubSysIds()
	if err != nil {
		log.WithField("confmap-update", configMapName).WithError(err).Warnf("Detection of Cgroup Subsystem Controllers failed")
		log.WithField("confmap-update", configMapName).Warn("Cgroup Subsystems IDs are unknown, advanced Cgroups tracking will be disabled")
		return err
	}

	// Detect deployment mode
	deployMode, err := cgroups.DetectDeploymentMode()
	if err != nil {
		log.WithField("confmap-update", configMapName).WithError(err).Warnf("Detection of deployment mode failed")
		log.WithField("confmap-update", configMapName).Warn("Deployment mode is unknown, advanced Cgroups tracking will be disabled")
		return err
	}

	mode := cgroups.DeploymentCode(deployMode)

	if option.Config.UsernameMetadata == int(option.USERNAME_METADATA_UNIX) &&
		mode != cgroups.DEPLOY_SD_SERVICE && mode != cgroups.DEPLOY_SD_USER {
		option.Config.UsernameMetadata = int(option.USERNAME_METADATA_DISABLED)
		log.WithFields(logrus.Fields{
			"confmap-update":  configMapName,
			"deployment.mode": mode.String(),
		}).Warn("Username resolution is not available for given deployment mode")
	}

	v := &TetragonConfValue{
		LogLevel:          uint32(logger.GetLogLevel()),
		TgCgrpHierarchy:   cgroups.GetCgrpHierarchyID(),
		TgCgrpv1SubsysIdx: cgroups.GetCgrpv1SubsystemIdx(),
		NSPID:             uint32(nspid),
		CgrpFsMagic:       cgroupFsMagic,
	}

	if err := UpdateConfMap(mapDir, v); err != nil {
		log.WithField("confmap-update", configMapName).WithError(err).Warnf("failed to update map")
		return err
	}

	if v.CgrpFsMagic == unix.CGROUP2_SUPER_MAGIC {
		log.WithFields(logrus.Fields{
			"confmap-update":     configMapName,
			"deployment.mode":    mode.String(),
			"log.level":          logrus.Level(v.LogLevel).String(),
			"cgroup.fs.magic":    cgroups.CgroupFsMagicStr(v.CgrpFsMagic),
			"cgroup.hierarchyID": v.TgCgrpHierarchy,
			"NSPID":              nspid,
		}).Info("Updated TetragonConf map successfully")
	} else {
		log.WithFields(logrus.Fields{
			"confmap-update":                configMapName,
			"deployment.mode":               mode.String(),
			"log.level":                     logrus.Level(v.LogLevel).String(),
			"cgroup.fs.magic":               cgroups.CgroupFsMagicStr(v.CgrpFsMagic),
			"cgroup.controller.name":        cgroups.GetCgrpControllerName(),
			"cgroup.controller.hierarchyID": v.TgCgrpHierarchy,
			"cgroup.controller.index":       v.TgCgrpv1SubsysIdx,
			"NSPID":                         nspid,
		}).Info("Updated TetragonConf map successfully")
	}

	return nil
}

func ReadTgRuntimeConf(mapDir string) (*TetragonConfValue, error) {
	configMap := base.GetTetragonConfMap()
	mapPath := filepath.Join(mapDir, configMap.Name)

	m, err := ebpf.LoadPinnedMap(mapPath, nil)
	if err != nil {
		return nil, err
	}

	defer m.Close()

	var v TetragonConfValue
	k := &TetragonConfKey{Key: 0}

	if err = m.Lookup(k, &v); err != nil {
		return nil, err
	}

	return &v, nil
}

// UpdateConfMap updates the configuration map with the provided value
func UpdateConfMap(mapDir string, v *TetragonConfValue) error {
	configMap := base.GetTetragonConfMap()
	mapPath := filepath.Join(mapDir, configMap.Name)
	mapSpec, err := confmapSpec()
	if err != nil {
		return err
	}

	m, err := program.LoadOrCreatePinnedMap(mapPath, mapSpec, configMap.IsOwner())
	if err != nil {
		return err
	}
	defer m.Close()

	k := &TetragonConfKey{Key: 0}
	err = m.Update(k, v, ebpf.UpdateAny)
	if err != nil {
		log.WithField("confmap-update", configMap.Name).WithError(err).Warn("Failed to update TetragonConf map")
		log.WithField("confmap-update", configMap.Name).Warn("Update TetragonConf map failed, advanced Cgroups tracking will be disabled")
		return err
	}

	return nil
}
