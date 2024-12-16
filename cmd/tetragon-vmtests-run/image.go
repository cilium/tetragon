// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/little-vm-helper/pkg/images"
	"github.com/cilium/little-vm-helper/pkg/step"
	"github.com/cilium/tetragon/pkg/vmtests"
	"github.com/sirupsen/logrus"
)

var (
	TetragonTesterBin   = "./tests/vmtests/tetragon-tester"
	TetragonTesterVmDir = "/sbin"
	TetragonTesterVmBin = filepath.Join(TetragonTesterVmDir, filepath.Base(TetragonTesterBin))
)

func buildFilesystemActions(fs []QemuFS, tmpDir string) ([]images.Action, error) {

	actions := make([]images.Action, 0, len(fs)+1)

	var b bytes.Buffer
	for _, fs := range fs {
		b.WriteString(fs.fstabEntry())
		act := images.Action{
			Op: &images.MkdirCommand{Dir: fs.vmMountpoint()},
		}
		actions = append(actions, act)
	}

	// NB: this is so that init can remount / rw
	b.WriteString("/dev/root\t/\text4\terrors=remount-ro\t0\t1\n")

	tmpFile := filepath.Join(tmpDir, "fstab")
	err := os.WriteFile(tmpFile, b.Bytes(), 0722)
	if err != nil {
		return nil, err
	}

	actions = append(actions, images.Action{
		Op: &images.CopyInCommand{
			LocalPath: tmpFile,
			RemoteDir: "/etc",
		},
	})

	return actions, nil
}

var tetragonTesterService = `
[Unit]
Description=Tetragon tester
After=network.target

[Service]
ExecStart=%s
Type=oneshot
# https://www.freedesktop.org/software/systemd/man/systemd.exec.html
# StandardOutput=file:%s
StandardOutput=tty
# StandardOutput=journal+console

[Install]
WantedBy=multi-user.target
`

func buildTesterService(rcnf *RunConf, tmpDir string) ([]images.Action, error) {
	service := fmt.Sprintf(tetragonTesterService, TetragonTesterVmBin, rcnf.testerOut)
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

func buildTesterActions(rcnf *RunConf, tmpDir string) ([]images.Action, error) {
	absTesterBin, err := filepath.Abs(TetragonTesterBin)
	if err != nil {
		return nil, fmt.Errorf("failed to get tetragon-tester full path: %w", err)
	}
	ret := []images.Action{
		{Op: &images.CopyInCommand{LocalPath: absTesterBin, RemoteDir: "/sbin/"}},
	}

	// NB: need to do this before we marshal the configuration
	if rcnf.btfFile != "" {
		absBtfFile, err := filepath.Abs(rcnf.btfFile)
		if err != nil {
			return nil, fmt.Errorf("failed to get btf file full path: %w", err)
		}
		ret = append(ret, images.Action{
			Op: &images.CopyInCommand{
				LocalPath: absBtfFile,
				RemoteDir: "/boot/",
			},
		})

		baseName := filepath.Base(rcnf.btfFile)
		rcnf.testerConf.BTFFile = filepath.Join("/boot", baseName)
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

	if !rcnf.useTetragonTesterInit && !rcnf.justBoot {
		acts, err := buildTesterService(rcnf, tmpDir)
		if err != nil {
			return nil, err
		}
		ret = append(ret, acts...)
	}

	return ret, nil
}

var networkConf = `
[Match]
Name=ens* enp* eth*
[Network]
DHCP=yes
`

func buildNetActions(tmpDir string) ([]images.Action, error) {
	ret := []images.Action{
		// Allow easy login for root user from ssh
		{Op: &images.AppendLineCommand{
			File: "/etc/ssh/sshd_config",
			Line: "PermitRootLogin yes",
		}},
		{Op: &images.AppendLineCommand{
			File: "/etc/ssh/sshd_config",
			Line: "PermitEmptyPasswords yes",
		}},
	}

	var b bytes.Buffer
	b.WriteString(networkConf)
	base := "20-interfaces.network"
	tmpFile := filepath.Join(tmpDir, base)
	err := os.WriteFile(tmpFile, b.Bytes(), 0644)
	if err != nil {
		return nil, err
	}

	dstDir := "/etc/systemd/network"
	ret = append(ret,
		images.Action{Op: &images.CopyInCommand{
			LocalPath: tmpFile,
			RemoteDir: dstDir,
		}},
		images.Action{Op: &images.ChmodCommand{
			File:        filepath.Join(dstDir, base),
			Permissions: "0644",
		}},
		images.Action{Op: &images.RunCommand{
			Cmd: "systemctl enable systemd-networkd.service",
		}},
	)

	return ret, nil
}

type NoNetworkCommand struct{}

func (rc *NoNetworkCommand) ActionOpName() string {
	return "no-network"
}

func (rc *NoNetworkCommand) ToSteps(s *images.StepConf) ([]step.Step, error) {
	return []step.Step{&images.VirtCustomizeStep{
		StepConf: s,
		Args:     []string{"--no-network"},
	}}, nil
}

func buildTestImage(log *logrus.Logger, rcnf *RunConf) error {

	imagesDir, baseImage := filepath.Split(rcnf.baseImageFilename)

	tmpDir, err := os.MkdirTemp("", "tetragon-vmtests-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	fsActions, err := buildFilesystemActions(rcnf.filesystems, tmpDir)
	if err != nil {
		return err
	}

	testerActions, err := buildTesterActions(rcnf, tmpDir)
	if err != nil {
		return err
	}

	netActions, err := buildNetActions(tmpDir)
	if err != nil {
		return err
	}

	actions := []images.Action{
		{Op: &NoNetworkCommand{}},
		{Op: &images.SetHostnameCommand{Hostname: rcnf.vmName}},
		{Op: &images.AppendLineCommand{
			File: "/etc/sysctl.d/local.conf",
			Line: "kernel.panic_on_rcu_stall=1",
		}},
	}
	actions = append(actions, fsActions...)
	actions = append(actions, testerActions...)
	actions = append(actions, netActions...)

	cnf := images.ImagesConf{
		Dir: imagesDir,
		// TODO: might be useful to modify the images builder so that
		// we can build this image using qemu-img -b
		Images: []images.ImgConf{{
			Name:    rcnf.testImageFilename(),
			Parent:  baseImage,
			Actions: actions,
		}},
	}

	forest, err := images.NewImageForest(&cnf, false)
	if err != nil {
		log.Fatal(err)
	}

	res := forest.BuildAllImages(&images.BuildConf{
		Log:          log,
		DryRun:       false,
		ForceRebuild: !rcnf.dontRebuildImage,
		MergeSteps:   true,
	})

	return res.Err()
}
