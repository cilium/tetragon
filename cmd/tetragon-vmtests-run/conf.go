// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package main

import (
	"path/filepath"

	"github.com/cilium/little-vm-helper/pkg/runner"
	"github.com/spf13/cobra"

	"github.com/cilium/tetragon/pkg/vmtests"
)

type GoTestConf struct {
	testConf
	testerConf      vmtests.Conf
	detailedResults bool
	keepAllLogs     bool
}

type testConf struct {
	runner.RunConf
	vmName                string
	baseImageFilename     string
	dontRebuildImage      bool
	useTetragonTesterInit bool
	qemuPrint             bool
	justBoot              bool
	justBuildImage        bool
	btfFile               string
	disableUnifiedCgroups bool

	filesystems []QemuFS
}

func cmdAddTestConfFlags(cmd *cobra.Command, cnf *testConf) {
	cmd.Flags().StringVar(&cnf.baseImageFilename, "base", "", "base image filename")
	cmd.MarkFlagRequired("base")
	cmd.Flags().StringVar(&cnf.vmName, "name", "tetragon", "new vm (and basis for the image name). New vm image will be in the directory of the base image")
	cmd.Flags().StringVar(&cnf.KernelFname, "kernel", "", "kernel filename to boot with. (if empty no -kernel option will be passed to qemu)")
	cmd.Flags().BoolVar(&cnf.dontRebuildImage, "dont-rebuild-image", false, "dont rebuild image")
	cmd.Flags().BoolVar(&cnf.useTetragonTesterInit, "use-tetragon-init", false, "use tetragon-vmtests-init as init process in the VM")
	cmd.Flags().BoolVar(&cnf.qemuPrint, "qemu-cmd-print", false, "Do not run the qemu command, just print it")
	cmd.Flags().BoolVar(&cnf.DisableHardwareAccel, "qemu-disable-kvm", false, "Do not use KVM acceleration, even if /dev/kvm exists")
	cmd.Flags().BoolVar(&cnf.justBoot, "just-boot", false, "Do not actually run any tests. Just setup everything and start the VM. User will be able to login to the VM.")
	cmd.Flags().BoolVar(&cnf.justBuildImage, "just-build-image", false, "Just build an image. Do not actually run any tests or boot the VM.")
	cmd.Flags().StringVar(&cnf.RootDev, "root-dev", "vda", "type of root device (hda or vda)")
	cmd.Flags().IntVar(&cnf.CPU, "cpu", 2, "number of vCPUs for the VM")
	cmd.Flags().StringVar(&cnf.Mem, "mem", "4G", "memory for the VM (e.g. 4G, 2048M)")
}

func (rc GoTestConf) testImageFilename() string {
	if ext := filepath.Ext(rc.vmName); ext == "" {
		return rc.vmName + ".qcow2"
	}
	return rc.vmName
}
