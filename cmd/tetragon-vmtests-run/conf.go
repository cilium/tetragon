package main

import (
	"path/filepath"

	"github.com/cilium/tetragon/pkg/vmtests"
)

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
	btfFile               string
	testerConf            vmtests.Conf

	filesystems []QemuFS
}

func (rc *RunConf) testImageFname() string {
	imagesDir := filepath.Dir(rc.baseFname)
	return filepath.Join(imagesDir, rc.testImage)
}
