// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package runner

import (
	"github.com/cilium/little-vm-helper/pkg/slogger"
)

type RunConf struct {
	// Image filename
	Image string
	// kernel filename to boot with. (if empty no -kernel option will be passed to qemu)
	KernelFname string
	// kernel append args to add when a kernel is passed to qemu
	KernelAppendArgs []string
	// Do not run the qemu command, just print it
	QemuPrint bool
	// Do not use hardware acceleration, KVM for Linux or HVF for macOS
	DisableHardwareAccel bool
	// Daemonize QEMU after initializing
	Daemonize bool
	// Log file for virtual console output
	ConsoleLogFile string

	// Print qemu command before running it
	Verbose bool

	// Disable the network connection to the VM
	DisableNetwork bool
	ForwardedPorts PortForwards

	Logger slogger.Logger

	HostMount string

	SerialPort int

	CPU int
	Mem string
	// Kind of CPU to use (e.g. host or kvm64)
	CPUKind string

	// RootDev is the type of device used for the root fs. Can be "hda" or "vda"
	RootDev string

	QemuMonitorPort int

	QemuArch string
}

func (rc *RunConf) testImageFname() string {
	return rc.Image
}
