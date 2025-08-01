// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package testutils

import (
	"os"

	"github.com/cilium/tetragon/pkg/cgroups"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/sensors/config/confmap"
)

func GetTgRuntimeConf() (*confmap.TetragonConfValue, error) {
	nspid := os.Getpid()

	// First let's detect cgroupfs magic
	cgroupFsMagic, err := cgroups.DetectCgroupFSMagic()
	if err != nil {
		return nil, err
	}

	// This must be called before probing cgroup configurations
	if err = cgroups.DiscoverSubSysIds(); err != nil { // nolint: staticcheck // DiscoverSubSysIds is always return non-nil error in windows
		return nil, err
	}

	// Detect deployment mode
	_, err = cgroups.DetectDeploymentMode()
	if err != nil {
		return nil, err
	}

	return &confmap.TetragonConfValue{
		LogLevel:          uint32(logger.GetLogLevel(logger.GetLogger())),
		TgCgrpHierarchy:   cgroups.GetCgrpHierarchyID(),
		TgCgrpv1SubsysIdx: cgroups.GetCgrpv1SubsystemIdx(),
		NSPID:             uint32(nspid),
		CgrpFsMagic:       cgroupFsMagic,
	}, nil
}

func ReadTgRuntimeConf(mapDir string) (*confmap.TetragonConfValue, error) {
	return confmap.ReadTgRuntimeConf(mapDir)
}
