// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package confmap

import (
	"fmt"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/cgroups"
	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/constants"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors/base"
	"github.com/cilium/tetragon/pkg/sensors/program"
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
	EnvVarsEnabled    uint64 `align:"env_vars_enabled"`     // Whether to read environment variables
	TgCgrpId          uint64 `align:"tg_cgrpid"`            // Tetragon cgroup ID
	CgrpFsMagic       uint64 `align:"cgrp_fs_magic"`        // Cgroupv1 or cgroupv2
}

var (
	log = logger.GetLogger()
)

// confmapSpec returns the spec for the configuration map
func confmapSpec() (*ebpf.MapSpec, error) {
	objName := config.ExecObj()
	objPath, err := config.FindProgramFile(objName)
	if err != nil {
		return nil, fmt.Errorf("loading spec for %s failed: %w", objPath, err)
	}
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
		log.Warn("Detection of Cgroupfs version failed", "confmap-update", configMapName, logfields.Error, err)
		log.Warn("Cgroupfs magic is unknown, advanced Cgroups tracking will be disabled", "confmap-update", configMapName)
		return err
	}

	// This must be called before probing cgroup configurations
	err = cgroups.DiscoverSubSysIds()
	if err != nil {
		log.Warn("Detection of Cgroup Subsystem Controllers failed", "confmap-update", configMapName, logfields.Error, err)
		log.Warn("Cgroup Subsystems IDs are unknown, advanced Cgroups tracking will be disabled", "confmap-update", configMapName)
		return err
	}

	// Detect deployment mode but do not fail
	deployMode, err := cgroups.DetectDeploymentMode()
	if err != nil {
		log.Warn("Detection of deployment mode failed", "confmap-update", configMapName, logfields.Error, err)
	}

	// Do not fail if deployment mode is unknown
	if deployMode == cgroups.DEPLOY_UNKNOWN {
		log.Warn("Deployment mode is unknown, advanced Cgroups tracking will be disabled", "confmap-update", configMapName)
	}

	if option.Config.UsernameMetadata == int(option.USERNAME_METADATA_UNIX) &&
		deployMode != cgroups.DEPLOY_SD_SERVICE && deployMode != cgroups.DEPLOY_SD_USER {
		option.Config.UsernameMetadata = int(option.USERNAME_METADATA_DISABLED)
		log.Warn("Username resolution is not available for given deployment mode", "confmap-update", configMapName,
			"deployment.mode", deployMode)
	}

	v := &TetragonConfValue{
		LogLevel:          uint32(logger.GetLogLevel(logger.GetLogger())),
		TgCgrpHierarchy:   cgroups.GetCgrpHierarchyID(),
		TgCgrpv1SubsysIdx: cgroups.GetCgrpv1SubsystemIdx(),
		NSPID:             uint32(nspid),
		CgrpFsMagic:       cgroupFsMagic,
	}

	if option.Config.EnableProcessEnvironmentVariables {
		v.EnvVarsEnabled = 1 // Set to 1 if environment variable reading is enabled
	}

	if err := UpdateConfMap(mapDir, v); err != nil {
		log.Warn("failed to update map", "confmap-update", configMapName, logfields.Error, err)
		return err
	}

	if v.CgrpFsMagic == constants.CGROUP2_SUPER_MAGIC {
		log.Info("Updated TetragonConf map successfully",
			"confmap-update", configMapName,
			"deployment.mode", deployMode.String(),
			"log.level", v.LogLevel,
			"cgroup.fs.magic", cgroups.CgroupFsMagicStr(v.CgrpFsMagic),
			"cgroup.hierarchyID", v.TgCgrpHierarchy,
			"NSPID", nspid)
	} else {
		log.Info("Updated TetragonConf map successfully",
			"confmap-update", configMapName,
			"deployment.mode", deployMode.String(),
			"log.level", v.LogLevel,
			"cgroup.fs.magic", cgroups.CgroupFsMagicStr(v.CgrpFsMagic),
			"cgroup.controller.name", cgroups.GetCgrpControllerName(),
			"cgroup.controller.hierarchyID", v.TgCgrpHierarchy,
			"cgroup.controller.index", v.TgCgrpv1SubsysIdx,
			"NSPID", nspid)
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
		log.Warn("Failed to update TetragonConf map", "confmap-update", configMap.Name, logfields.Error, err)
		log.Warn("Update TetragonConf map failed, advanced Cgroups tracking will be disabled", "confmap-update", configMap.Name)
		return err
	}

	return nil
}
