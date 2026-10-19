// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package lvh

import (
	"fmt"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/cilium/little-vm-helper/pkg/arch"
	"github.com/cilium/little-vm-helper/pkg/runner"
	"github.com/cilium/little-vm-helper/pkg/slogger"
	"golang.org/x/sys/unix"
)

var (
	TetragonTesterBin   = "./tests/vmtests/tetragon-tester"
	TetragonTesterVMDir = "/sbin"
	TetragonTesterVMBin = filepath.Join(TetragonTesterVMDir, filepath.Base(TetragonTesterBin))
)

// BuildQemuArgs wraps runner.BuildQemuArgs with the vmtests additions: the
// kernel arguments and the shared filesystems.
func BuildQemuArgs(log slogger.Logger, cnf Conf) ([]string, error) {
	// cnf is a copy, but its slices still share their arrays with the caller
	cnf.KernelAppendArgs = slices.Clone(cnf.KernelAppendArgs)
	if cnf.KernelFname != "" {
		if cnf.DisableUnifiedCgroups {
			cnf.KernelAppendArgs = append(cnf.KernelAppendArgs, "systemd.unified_cgroup_hierarchy=0")
		}
		if cnf.UseTetragonTesterInit {
			cnf.KernelAppendArgs = append(cnf.KernelAppendArgs, "init="+TetragonTesterBin)
		}
	}

	// the new image is in the base image folder
	cnf.Image = filepath.Join(filepath.Dir(cnf.BaseImageFilename), cnf.imageFilename())

	qemuArgs, err := runner.BuildQemuArgs(log, &cnf.RunConf)
	if err != nil {
		return nil, err
	}

	for _, fs := range cnf.Filesystems {
		qemuArgs = append(qemuArgs, fs.QemuArgs()...)
	}

	return qemuArgs, nil
}

// QemuCommand returns the qemu binary of this host and the arguments that
// boot the image.
func QemuCommand(log slogger.Logger, cnf Conf) (string, []string, error) {
	runtimeArch, err := arch.NewArch(runtime.GOARCH)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create lvh arch: %w", err)
	}
	args, err := BuildQemuArgs(log, cnf)
	if err != nil {
		return "", nil, fmt.Errorf("failed to build qemu args: %w", err)
	}
	return runtimeArch.QemuBinary(), args, nil
}

// QemuPrintCmd prints the qemu command line.
func QemuPrintCmd(qemuBin string, qemuArgs []string) {
	var sb strings.Builder
	sb.WriteString(qemuBin)
	for _, arg := range qemuArgs {
		sb.WriteString(" ")
		if len(arg) > 0 && arg[0] == '-' {
			sb.WriteString("\\\n\t")
		}
		sb.WriteString(arg)
	}

	fmt.Printf("%s\n", sb.String())
}

// QemuJustBoot replaces the process with qemu, so the user can log in to the
// VM.
func QemuJustBoot(qemuBin string, qemuArgs []string) error {
	bin := filepath.Join("/usr/bin/", qemuBin)
	args := []string{qemuBin}
	args = append(args, qemuArgs...)
	env := []string{}
	return unix.Exec(bin, args, env)
}
