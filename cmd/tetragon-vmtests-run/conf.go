// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/little-vm-helper/pkg/images"
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
	pullBaseImage         bool
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
	cmd.Flags().BoolVar(&cnf.pullBaseImage, "enable-pull-base", true, "pull base image from an OCI repo, if it is not found locally")
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

func (tc testConf) testImageFilename() string {
	if ext := filepath.Ext(tc.vmName); ext == "" {
		return tc.vmName + ".qcow2"
	}
	return tc.vmName
}

// if the base image does not exist, attempt to pull it (if pullBaseImage is set)
func (tc *testConf) maybePullBaseImage(dirName string) error {
	if !tc.pullBaseImage {
		return nil
	}

	if _, err := os.Stat(tc.baseImageFilename); !errors.Is(err, os.ErrNotExist) {
		return nil
	}

	// Not a local file reference, could this be an OCI image?
	ctx := context.Background()
	pcnf := images.PullConf{
		Image:     tc.baseImageFilename,
		TargetDir: dirName,
		Platform:  tc.QemuArch,
	}
	if err := images.PullImage(ctx, pcnf); err != nil {
		return fmt.Errorf("unable to pull image: %w (%+v)", err, pcnf)
	}
	result, err := images.ExtractImage(ctx, pcnf)
	if err != nil {
		return fmt.Errorf("unable to extract image: %w (%+v)", err, pcnf)
	}
	tc.baseImageFilename = result.Images[0]
	return nil
}
