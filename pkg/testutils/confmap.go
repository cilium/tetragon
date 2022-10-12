// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package testutils

import (
	"os"
	"path/filepath"
	"time"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/cgroups"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/sensors/base"
	"github.com/cilium/tetragon/pkg/sensors/config/confmap"
	"github.com/sirupsen/logrus"
)

var (
	log = logger.GetLogger()
)

func GetTgRuntimeConf() (*confmap.TetragonConfValue, error) {
	nspid := os.Getpid()

	// First let's detect cgroupfs magic
	cgroupFsMagic, err := cgroups.DetectCgroupFSMagic()
	if err != nil {
		return nil, err
	}

	// This must be called before probing cgroup configurations
	err = cgroups.DiscoverSubSysIds()
	if err != nil {
		return nil, err
	}

	// Detect deployment mode
	_, err = cgroups.DetectDeploymentMode()
	if err != nil {
		return nil, err
	}

	return &confmap.TetragonConfValue{
		LogLevel:        uint32(logger.GetLogLevel()),
		TgCgrpHierarchy: cgroups.GetCgrpHierarchyID(),
		TgCgrpSubsysIdx: cgroups.GetCgrpSubsystemIdx(),
		NSPID:           uint32(nspid),
		CgrpFsMagic:     cgroupFsMagic,
	}, nil
}

// Test `tg_conf_map` BPF MAP with explicit values
func UpdateTgRuntimeConf(mapDir string, v *confmap.TetragonConfValue) error {
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

	k := &confmap.TetragonConfKey{Key: 0}
	err = m.Update(k, v)
	if err != nil {
		log.WithField("confmap-update", configMap.Name).WithError(err).Warn("Failed to update TetragonConf map")
		return err
	}

	log.WithFields(logrus.Fields{
		"confmap-update":                configMap.Name,
		"log.level":                     logrus.Level(v.LogLevel).String(),
		"cgroup.fs.magic":               cgroups.CgroupFsMagicStr(v.CgrpFsMagic),
		"cgroup.controller.name":        cgroups.GetCgrpControllerName(),
		"cgroup.controller.hierarchyID": v.TgCgrpHierarchy,
		"cgroup.controller.index":       v.TgCgrpSubsysIdx,
		"cgroup.ID":                     v.TgCgrpId,
		"NSPID":                         v.NSPID,
	}).Debug("Updated TetragonConf map successfully")

	return nil
}

func ReadTgRuntimeConf(mapDir string) (*confmap.TetragonConfValue, error) {
	return confmap.ReadTgRuntimeConf(mapDir)
}
