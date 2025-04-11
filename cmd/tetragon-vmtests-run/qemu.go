// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package main

import (
	"path/filepath"

	"github.com/cilium/little-vm-helper/pkg/runner"
	"github.com/sirupsen/logrus"
)

// buildQemuArgs is a wrapper around LVH's runner.BuildQemuArgs and also handles
// custom configuration from vmtests
func buildQemuArgs(log *logrus.Logger, rcnf RunConf) ([]string, error) {
	if rcnf.KernelFname != "" {
		if rcnf.disableUnifiedCgroups {
			rcnf.KernelAppendArgs = append(rcnf.KernelAppendArgs, "systemd.unified_cgroup_hierarchy=0")
		}
		if rcnf.useTetragonTesterInit {
			rcnf.KernelAppendArgs = append(rcnf.KernelAppendArgs, "init="+TetragonTesterBin)
		}
	}

	rcnf.CPU = 2
	rcnf.Mem = "4G"
	// the new image is in the base image folder
	rcnf.Image = filepath.Join(filepath.Dir(rcnf.baseImageFilename), rcnf.testImageFilename())

	qemuArgs, err := runner.BuildQemuArgs(log, &rcnf.RunConf)
	if err != nil {
		return nil, err
	}

	for _, fs := range rcnf.filesystems {
		qemuArgs = append(qemuArgs, fs.qemuArgs()...)
	}

	return qemuArgs, nil
}
