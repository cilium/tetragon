package main

import (
	"path/filepath"

	"github.com/cilium/little-vm-helper/pkg/runner"
	"github.com/cilium/tetragon/pkg/vmtests"
)

// NB: we should use lvh's RunConf to avoid duplicating code
type RunConf struct {
	testImage             string
	baseFname             string
	kernelFname           string
	dontRebuildImage      bool
	useTetragonTesterInit bool
	testerOut             string
	qemuPrint             bool
	justBoot              bool
	justBuildImage        bool
	disableKVM            bool
	enableHVF             bool
	btfFile               string
	disableUnifiedCgroups bool
	portForwards          runner.PortForwards
	testerConf            vmtests.Conf

	filesystems []QemuFS
}

func (rc *RunConf) testImageFname() string {
	imagesDir := filepath.Dir(rc.baseFname)
	return filepath.Join(imagesDir, rc.testImage)
}
