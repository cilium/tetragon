// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

// Package lvh holds the little-vm-helper plumbing that the vmtests runners
// share: the VM configuration and its flags, the qemu command, the
// filesystems shared with the VM, and the image actions every test image
// needs.
package lvh

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/little-vm-helper/pkg/images"
	"github.com/cilium/little-vm-helper/pkg/runner"
	"github.com/spf13/cobra"
)

// Conf is the VM configuration of a test run.
type Conf struct {
	runner.RunConf
	VMName                string
	BaseImageFilename     string
	PullBaseImage         bool
	DontRebuildImage      bool
	UseTetragonTesterInit bool
	QemuPrint             bool
	JustBoot              bool
	JustBuildImage        bool
	BTFFile               string
	DisableUnifiedCgroups bool

	Filesystems []QemuFS
}

// AddFlags registers the VM flags on cmd.
func AddFlags(cmd *cobra.Command, cnf *Conf) {
	cmd.Flags().StringVar(&cnf.BaseImageFilename, "base", "", "base image filename")
	cmd.MarkFlagRequired("base")
	cmd.Flags().BoolVar(&cnf.PullBaseImage, "enable-pull-base", true, "pull base image from an OCI repo, if it is not found locally")
	cmd.Flags().StringVar(&cnf.VMName, "name", "tetragon", "new vm (and basis for the image name). New vm image will be in the directory of the base image")
	cmd.Flags().StringVar(&cnf.KernelFname, "kernel", "", "kernel filename to boot with. (if empty no -kernel option will be passed to qemu)")
	cmd.Flags().BoolVar(&cnf.DontRebuildImage, "dont-rebuild-image", false, "dont rebuild image")
	cmd.Flags().BoolVar(&cnf.UseTetragonTesterInit, "use-tetragon-init", false, "use tetragon-vmtests-init as init process in the VM")
	cmd.Flags().BoolVar(&cnf.QemuPrint, "qemu-cmd-print", false, "Do not run the qemu command, just print it")
	cmd.Flags().BoolVar(&cnf.DisableHardwareAccel, "qemu-disable-kvm", false, "Do not use KVM acceleration, even if /dev/kvm exists")
	cmd.Flags().BoolVar(&cnf.JustBoot, "just-boot", false, "Do not actually run any tests. Just setup everything and start the VM. User will be able to login to the VM.")
	cmd.Flags().BoolVar(&cnf.JustBuildImage, "just-build-image", false, "Just build an image. Do not actually run any tests or boot the VM.")
	cmd.Flags().StringVar(&cnf.RootDev, "root-dev", "vda", "type of root device (hda or vda)")
	cmd.Flags().IntVar(&cnf.CPU, "cpu", 2, "number of vCPUs for the VM")
	cmd.Flags().StringVar(&cnf.Mem, "mem", "4G", "memory for the VM (e.g. 4G, 2048M)")
}

// imageFilename is the name of the image built from the base image.
func (c *Conf) imageFilename() string {
	if ext := filepath.Ext(c.VMName); ext == "" {
		return c.VMName + ".qcow2"
	}
	return c.VMName
}

// MaybePullBaseImage pulls the base image into dir when PullBaseImage is set
// and the image is not a local file.
func (c *Conf) MaybePullBaseImage(ctx context.Context, dir string) error {
	if !c.PullBaseImage {
		return nil
	}

	if _, err := os.Stat(c.BaseImageFilename); !errors.Is(err, os.ErrNotExist) {
		return nil
	}

	// Not a local file reference, could this be an OCI image?
	pcnf := images.PullConf{
		Image:     c.BaseImageFilename,
		TargetDir: dir,
		Platform:  c.QemuArch,
	}
	if err := images.PullImage(ctx, pcnf); err != nil {
		return fmt.Errorf("unable to pull image: %w (%+v)", err, pcnf)
	}
	result, err := images.ExtractImage(ctx, pcnf)
	if err != nil {
		return fmt.Errorf("unable to extract image: %w (%+v)", err, pcnf)
	}
	c.BaseImageFilename = result.Images[0]
	return nil
}
