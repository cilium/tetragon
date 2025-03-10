package arch

import (
	"fmt"
	"runtime"
)

type Arch string

func NewArch(arch string) (Arch, error) {
	switch arch {
	case "amd64", "arm64":
		return Arch(arch), nil
	default:
		return Arch(""), fmt.Errorf("unsupported architecture %s", arch)
	}
}

// Target returns the Linux Makefile target to build the kernel, for historical
// reasons, those are different between architectures.
func (a Arch) Target() string {
	switch a {
	case "amd64":
		return "bzImage"
	case "arm64":
		return "Image.gz"
	default:
		panic(fmt.Sprintf("Target(): Unsupported arch: %s", a))
	}
}

func (a Arch) CrossCompiling() bool {
	return !a.IsNative()
}

func (a Arch) IsNative() bool {
	return string(a) == runtime.GOARCH
}

func (a Arch) CrossCompileMakeArgs() []string {
	if !a.CrossCompiling() {
		return nil
	}

	switch a {
	case "arm64":
		return []string{"ARCH=arm64", "CROSS_COMPILE=aarch64-linux-gnu-"}
	case "amd64":
		return []string{"ARCH=x86_64", "CROSS_COMPILE=x86_64-linux-gnu-"}
	default:
		panic(fmt.Sprintf("CrossCompileMakeArgs(): Unsupported arch: %s", a))
	}
}

func (a Arch) QemuBinary() string {
	switch a {
	case "amd64":
		return "qemu-system-x86_64"
	case "arm64":
		return "qemu-system-aarch64"
	default:
		panic(fmt.Sprintf("QemuBinary(): Unsupported arch: %s", a))
	}
}

// Console returns the name of the device for the first serial port.
func (a Arch) Console() string {
	switch a {
	case "amd64":
		return "ttyS0"
	case "arm64":
		return "ttyAMA0"
	default:
		panic(fmt.Sprintf("Console(): Unsupported arch: %s", a))
	}
}

// AppendArchSpecificQemuArgs appends Qemu arguments to the input that are
// specific to the architecture lvh is running on. For example on ARM64, Qemu
// needs some precision on the -machine option to start.
func (a Arch) AppendArchSpecificQemuArgs(qemuArgs []string) []string {
	switch a {
	case "arm64":
		return append(qemuArgs, "-machine", "virt")
	case "amd64":
		return qemuArgs
	default:
		panic(fmt.Sprintf("AppendArchSpecificQemuArgs(): Unsupported arch: %s", a))
	}
}

// AppendCPUKind appends the -cpu type if needed, historically amd64 has used no
// specific kind when running without KVM, and using kvm64 when running with
// KVM. However, arm64 needs -cpu max in both cases to start properly.
func (a Arch) AppendCPUKind(qemuArgs []string, kvmEnabled bool, cpuKind string) []string {
	if cpuKind != "" {
		return append(qemuArgs, "-cpu", cpuKind)
	}
	switch a {
	case "amd64":
		if kvmEnabled {
			return append(qemuArgs, "-cpu", "kvm64")
		}
	case "arm64":
		return append(qemuArgs, "-cpu", "max")
	default:
		panic(fmt.Sprintf("AppendCPUKind(): Unsupported arch: %s", a))
	}
	return qemuArgs
}

// Bootable returns the arch-dependent default value in case the pointer is nil,
// so option is unconfigured. Typically arm64 should not be bootable by default
// because we didn't take the time to find a bootloader that was arm64
// compatible so far.
func (a Arch) Bootable(bootable *bool) bool {
	if bootable == nil {
		return string(a) == "amd64"
	}
	return *bootable
}
