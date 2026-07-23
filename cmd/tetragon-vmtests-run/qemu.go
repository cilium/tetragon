// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/cilium/little-vm-helper/pkg/runner"
	"github.com/cilium/little-vm-helper/pkg/slogger"
	"golang.org/x/sys/unix"
)

// buildQemuArgs is a wrapper around LVH's runner.BuildQemuArgs and also handles
// custom configuration from vmtests
func buildQemuArgs(log slogger.Logger, rcnf testConf) ([]string, error) {
	if rcnf.KernelFname != "" {
		if rcnf.disableUnifiedCgroups {
			rcnf.KernelAppendArgs = append(rcnf.KernelAppendArgs, "systemd.unified_cgroup_hierarchy=0")
		}
		if rcnf.useTetragonTesterInit {
			rcnf.KernelAppendArgs = append(rcnf.KernelAppendArgs, "init="+TetragonTesterBin)
		}
	}

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

func qemuPrintCmd(qemuBin string, qemuArgs []string) {
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

func qemuJustBoot(qemuBin string, qemuArgs []string) error {
	bin := filepath.Join("/usr/bin/", qemuBin)
	args := []string{qemuBin}
	args = append(args, qemuArgs...)
	env := []string{}
	return unix.Exec(bin, args, env)
}
