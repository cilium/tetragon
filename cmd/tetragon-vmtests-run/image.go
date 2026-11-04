// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/little-vm-helper/pkg/images"
	"github.com/cilium/little-vm-helper/pkg/slogger"

	"github.com/cilium/tetragon/pkg/vmtests"
	"github.com/cilium/tetragon/pkg/vmtests/lvh"
)

var tetragonTesterService = `
[Unit]
Description=Tetragon tester
After=network.target

[Service]
ExecStart=%s
Type=oneshot
# https://www.freedesktop.org/software/systemd/man/systemd.exec.html
StandardOutput=tty
# StandardOutput=journal+console

[Install]
WantedBy=multi-user.target
`

func buildTesterService(tmpDir string) ([]images.Action, error) {
	execStart := lvh.TetragonTesterVMBin + " gotest"
	service := fmt.Sprintf(tetragonTesterService, execStart)
	var b bytes.Buffer
	b.WriteString(service)

	tmpFile := filepath.Join(tmpDir, "tetragon-tester.service")
	err := os.WriteFile(tmpFile, b.Bytes(), 0722)
	if err != nil {
		return nil, err
	}

	actions := []images.Action{
		{Op: &images.CopyInCommand{
			LocalPath: tmpFile,
			RemoteDir: "/etc/systemd/system",
		}},
		/*
			{Op: &images.RunCommand{
				Cmd: "sed -i  's/^#LogColor=yes/LogColor=no/' /etc/systemd/system.conf",
			}},
		*/
	}

	enableTester := images.Action{Op: &images.RunCommand{Cmd: "systemctl enable tetragon-tester.service"}}
	actions = append(actions, enableTester)

	return actions, nil
}

func buildTesterActions(rcnf *GoTestConf, tmpDir string) ([]images.Action, error) {
	absTesterBin, err := filepath.Abs(lvh.TetragonTesterBin)
	if err != nil {
		return nil, fmt.Errorf("failed to get tetragon-tester full path: %w", err)
	}
	ret := []images.Action{
		{Op: &images.CopyInCommand{LocalPath: absTesterBin, RemoteDir: "/sbin/"}},
	}

	// NB: need to do this before we marshal the configuration
	if rcnf.BTFFile != "" {
		act, vmBTFFile, err := lvh.BTFAction(rcnf.BTFFile)
		if err != nil {
			return nil, err
		}
		ret = append(ret, act)
		rcnf.testerConf.BTFFile = vmBTFFile
	}

	confB, err := json.MarshalIndent(&rcnf.testerConf, "", "    ")
	if err != nil {
		return nil, err
	}

	tmpConfFile := filepath.Join(tmpDir, filepath.Base(vmtests.ConfFile))
	remoteConfDir := filepath.Dir(vmtests.ConfFile)
	if err := os.WriteFile(tmpConfFile, confB, 0722); err != nil {
		return nil, err
	}

	ret = append(ret, images.Action{
		Op: &images.CopyInCommand{LocalPath: tmpConfFile, RemoteDir: remoteConfDir},
	})

	if !rcnf.UseTetragonTesterInit && !rcnf.JustBoot {
		acts, err := buildTesterService(tmpDir)
		if err != nil {
			return nil, err
		}
		ret = append(ret, acts...)
	}

	return ret, nil
}

func buildTestImage(log slogger.Logger, rcnf *GoTestConf) error {
	tmpDir, err := os.MkdirTemp("", "tetragon-vmtests-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	fsActions, err := lvh.FilesystemActions(rcnf.Filesystems, tmpDir)
	if err != nil {
		return err
	}

	testerActions, err := buildTesterActions(rcnf, tmpDir)
	if err != nil {
		return err
	}

	netActions, err := lvh.NetActions(tmpDir)
	if err != nil {
		return err
	}

	actions := lvh.BaseActions(&rcnf.Conf)
	actions = append(actions, fsActions...)
	actions = append(actions, testerActions...)
	actions = append(actions, netActions...)

	return lvh.BuildImage(log, &rcnf.Conf, actions, !rcnf.DontRebuildImage)
}
