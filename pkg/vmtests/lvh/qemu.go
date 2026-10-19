// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package lvh

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
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
	TetragonTesterVMBin = filepath.Join("/sbin", filepath.Base(TetragonTesterBin))
)

// buildQemuArgs adds the kernel arguments and the shared filesystems.
func buildQemuArgs(log slogger.Logger, cnf Conf) ([]string, error) {
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

// QemuCommand returns the qemu binary and arguments that boot the image.
func QemuCommand(log slogger.Logger, cnf Conf) (string, []string, error) {
	runtimeArch, err := arch.NewArch(runtime.GOARCH)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create lvh arch: %w", err)
	}
	args, err := buildQemuArgs(log, cnf)
	if err != nil {
		return "", nil, fmt.Errorf("failed to build qemu args: %w", err)
	}
	return runtimeArch.QemuBinary(), args, nil
}

// RunQemu boots the image and waits for the VM to power off. A cancelled ctx
// wins over the qemu error it causes.
func RunQemu(ctx context.Context, qemuBin string, qemuArgs []string, stdout, stderr io.Writer) error {
	cmd := exec.CommandContext(ctx, qemuBin, qemuArgs...)
	out, errOut := bufio.NewWriter(stdout), bufio.NewWriter(stderr)
	cmd.Stdout, cmd.Stderr = out, errOut
	err := cmd.Run()
	out.Flush()
	errOut.Flush()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		return fmt.Errorf("qemu failed: %w", err)
	}
	return nil
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
