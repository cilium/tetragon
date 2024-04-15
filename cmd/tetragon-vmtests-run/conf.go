// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"fmt"
	"path/filepath"

	"github.com/cilium/little-vm-helper/pkg/runner"
	"github.com/cilium/tetragon/pkg/vmtests"
)

type RunConf struct {
	runner.RunConf
	vmName                string
	baseImageFilename     string
	dontRebuildImage      bool
	useTetragonTesterInit bool
	testerOut             string
	qemuPrint             bool
	justBoot              bool
	justBuildImage        bool
	btfFile               string
	disableUnifiedCgroups bool
	testerConf            vmtests.Conf
	detailedResults       bool
	keepAllLogs           bool

	filesystems []QemuFS
}

func (rc RunConf) testImageFilename() string {
	if ext := filepath.Ext(rc.vmName); ext == "" {
		return fmt.Sprintf("%s.qcow2", rc.vmName)
	}
	return rc.vmName
}
