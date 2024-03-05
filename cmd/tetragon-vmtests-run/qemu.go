// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
)

func buildQemuArgs(log *logrus.Logger, rcnf *RunConf) ([]string, error) {
	qemuArgs := []string{
		// no need for all the default devices
		"-nodefaults",
		// no need display (-nographics seems a bit slower)
		"-display", "none",
		// don't reboot, just exit
		"-no-reboot",
		// cpus, memory
		"-smp", "2", "-m", "4G",
	}

	if rcnf.enableHVF {
		log.Info("HVF enabled")
		qemuArgs = append(qemuArgs, "-accel", "hvf")
	} else if !rcnf.disableKVM {
		// quick-and-dirty kvm detection
		if f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0755); err == nil {
			qemuArgs = append(qemuArgs, "-enable-kvm", "-cpu", "kvm64")
			f.Close()
		} else {
			log.Infof("KVM disabled (%v)", err)
		}
	}

	var kernelRoot string
	switch rcnf.rootDev {
	case "hda":
		qemuArgs = append(qemuArgs, "-hda", rcnf.testImageFname())
		kernelRoot = "/dev/sda"
	case "vda":
		qemuArgs = append(qemuArgs, "-drive", fmt.Sprintf("file=%s,if=virtio,index=0,media=disk", rcnf.testImageFname()))
		kernelRoot = "/dev/vda"
	default:
		return nil, fmt.Errorf("invalid root device: %s", rcnf.rootDev)
	}

	if rcnf.kernelFname != "" {
		appendArgs := []string{
			fmt.Sprintf("root=%s", kernelRoot),
			"console=ttyS0",
			"earlyprintk=ttyS0",
			"panic=-1",
		}
		if rcnf.disableUnifiedCgroups {
			appendArgs = append(appendArgs, "systemd.unified_cgroup_hierarchy=0")
		}
		if rcnf.useTetragonTesterInit {
			appendArgs = append(appendArgs, fmt.Sprintf("init=%s", TetragonTesterBin))
		}
		qemuArgs = append(qemuArgs,
			"-kernel", rcnf.kernelFname,
			"-append", strings.Join(appendArgs, " "),
		)
	}

	// NB: not sure what the best option is here, this is from trial-and-error
	qemuArgs = append(qemuArgs,
		"-serial", "mon:stdio",
		"-device", "virtio-serial-pci",
	)

	for _, fs := range rcnf.filesystems {
		qemuArgs = append(qemuArgs, fs.qemuArgs()...)
	}

	if len(rcnf.portForwards) > 0 {
		qemuArgs = append(qemuArgs, rcnf.portForwards.QemuArgs()...)
	}

	return qemuArgs, nil
}
