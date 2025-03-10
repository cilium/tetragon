// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package runner

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/cilium/little-vm-helper/pkg/arch"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func getArch(rcnf *RunConf) (arch.Arch, error) {
	a := rcnf.QemuArch
	if a == "" {
		a = runtime.GOARCH
	}

	return arch.NewArch(a)
}

func BuildQemuArgs(log *logrus.Logger, rcnf *RunConf) ([]string, error) {
	qemuArgs := []string{
		// no need for all the default devices
		"-nodefaults",
		// no need display (-nographics seems a bit slower)
		"-display", "none",
		// don't reboot, just exit
		"-no-reboot",
		// cpus, memory
		"-smp", fmt.Sprintf("%d", rcnf.CPU), "-m", rcnf.Mem,
	}

	qArch, err := getArch(rcnf)
	if err != nil {
		return nil, err
	}
	qemuArgs = qArch.AppendArchSpecificQemuArgs(qemuArgs)

	// quick-and-dirty kvm detection
	kvmEnabled := false
	if !rcnf.DisableHardwareAccel && qArch.IsNative() {
		switch runtime.GOOS {
		case "linux":
			if f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0755); err == nil {
				qemuArgs = append(qemuArgs, "-enable-kvm")
				f.Close()
				kvmEnabled = true
			} else {
				log.Info("KVM disabled")
			}
		case "darwin":
			qemuArgs = append(qemuArgs, "-accel", "hvf")
		}
	}

	qemuArgs = qArch.AppendCPUKind(qemuArgs, kvmEnabled, rcnf.CPUKind)

	if rcnf.SerialPort != 0 {
		qemuArgs = append(qemuArgs,
			"-serial",
			fmt.Sprintf("telnet:localhost:%d,server,nowait", rcnf.SerialPort))
	}

	if rcnf.ConsoleLogFile != "" {
		qemuArgs = append(qemuArgs,
			"-serial",
			fmt.Sprintf("file:%s", rcnf.ConsoleLogFile))
	}

	var kernelRoot string
	switch rcnf.RootDev {
	case "hda":
		qemuArgs = append(qemuArgs, "-hda", rcnf.testImageFname())
		kernelRoot = "/dev/sda"
	case "vda":
		qemuArgs = append(qemuArgs, "-drive", fmt.Sprintf("file=%s,if=virtio,index=0,media=disk", rcnf.testImageFname()))
		kernelRoot = "/dev/vda"
	default:
		return nil, fmt.Errorf("invalid root device: %s", rcnf.RootDev)
	}

	if rcnf.KernelFname != "" {
		console := qArch.Console()
		if err != nil {
			return nil, fmt.Errorf("failed retrieving console name: %w", err)
		}

		appendArgs := []string{
			fmt.Sprintf("root=%s", kernelRoot),
			fmt.Sprintf("console=%s", console),
			"earlyprintk=ttyS0",
			"panic=-1",
		}
		appendArgs = append(appendArgs, rcnf.KernelAppendArgs...)
		qemuArgs = append(qemuArgs,
			"-kernel", rcnf.KernelFname,
			"-append", strings.Join(appendArgs, " "),
		)
	}

	if !rcnf.DisableNetwork {
		qemuArgs = append(qemuArgs, rcnf.ForwardedPorts.QemuArgs()...)
	}

	if !rcnf.Daemonize {
		qemuArgs = append(qemuArgs,
			"-serial", "mon:stdio",
			"-device", "virtio-serial-pci",
		)
	} else {
		qemuArgs = append(qemuArgs, "-daemonize")
	}

	if rcnf.QemuMonitorPort != 0 {
		arg := fmt.Sprintf("tcp:localhost:%d,server,nowait", rcnf.QemuMonitorPort)
		qemuArgs = append(qemuArgs, "-monitor", arg)
	}

	if len(rcnf.HostMount) > 0 {
		qemuArgs = append(qemuArgs,
			"-fsdev", fmt.Sprintf("local,id=host_id,path=%s,security_model=none", rcnf.HostMount),
			"-device", "virtio-9p-pci,fsdev=host_id,mount_tag=host_mount",
		)
	}

	return qemuArgs, nil
}

func StartQemu(rcnf RunConf) error {
	qArch, err := getArch(&rcnf)
	if err != nil {
		return err
	}

	qemuBin := qArch.QemuBinary()
	qemuArgs, err := BuildQemuArgs(rcnf.Logger, &rcnf)
	if err != nil {
		return err
	}

	if rcnf.QemuPrint || rcnf.Verbose {
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
		// We don't want to return early if running in verbose mode
		if rcnf.QemuPrint {
			return nil
		}
	}

	qemuPath, err := exec.LookPath(qemuBin)
	if err != nil {
		return err
	}

	return unix.Exec(qemuPath, append([]string{qemuBin}, qemuArgs...), nil)
}
