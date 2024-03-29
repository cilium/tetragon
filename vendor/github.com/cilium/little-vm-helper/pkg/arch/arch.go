package arch

import (
	"fmt"
	"runtime"
)

var ErrUnsupportedArch = fmt.Errorf("unsupported architecture: %s", runtime.GOARCH)

// Target returns the Linux Makefile target to build the kernel, for historical
// reasons, those are different between architectures.
func Target(arch string) (string, error) {
	if arch == "" {
		arch = runtime.GOARCH
	}
	switch arch {
	case "amd64":
		return "bzImage", nil
	case "arm64":
		return "Image.gz", nil
	default:
		return "", fmt.Errorf("unsupported architecture for Makefile target: %s", arch)
	}
}

func CrossCompiling(targetArch string) bool {
	return targetArch != "" && targetArch != runtime.GOARCH
}

func CrossCompileMakeArgs(targetArch string) ([]string, error) {
	if !CrossCompiling(targetArch) {
		return nil, nil
	}

	switch targetArch {
	case "arm64":
		return []string{"ARCH=arm64", "CROSS_COMPILE=aarch64-linux-gnu-"}, nil
	case "amd64":
		return []string{"ARCH=x86_64", "CROSS_COMPILE=x86_64-linux-gnu-"}, nil
	}
	return nil, fmt.Errorf("unsupported architecture for cross-compilation: %s", targetArch)
}

func QemuBinary() (string, error) {
	switch runtime.GOARCH {
	case "amd64":
		return "qemu-system-x86_64", nil
	case "arm64":
		return "qemu-system-aarch64", nil
	default:
		return "", ErrUnsupportedArch
	}
}

// Console returns the name of the device for the first serial port.
func Console() (string, error) {
	switch runtime.GOARCH {
	case "amd64":
		return "ttyS0", nil
	case "arm64":
		return "ttyAMA0", nil
	default:
		return "", ErrUnsupportedArch
	}
}

// AppendArchSpecificQemuArgs appends Qemu arguments to the input that are
// specific to the architecture lvh is running on. For example on ARM64, Qemu
// needs some precision on the -machine option to start.
func AppendArchSpecificQemuArgs(qemuArgs []string) []string {
	switch runtime.GOARCH {
	case "arm64":
		return append(qemuArgs, "-machine", "virt")
	default:
		return qemuArgs
	}
}

// AppendCPUKind appends the -cpu type if needed, historically amd64 has used no
// specific kind when running without KVM, and using kvm64 when running with
// KVM. However, arm64 needs -cpu max in both cases to start properly.
func AppendCPUKind(qemuArgs []string, kvmEnabled bool, cpuKind string) []string {
	if cpuKind != "" {
		return append(qemuArgs, "-cpu", cpuKind)
	}
	switch runtime.GOARCH {
	case "amd64":
		if kvmEnabled {
			return append(qemuArgs, "-cpu", "kvm64")
		}
	case "arm64":
		return append(qemuArgs, "-cpu", "max")
	}
	return qemuArgs
}

// Bootable returns the arch-dependent default value in case the pointer is nil,
// so option is unconfigured. Typically arm64 should not be bootable by default
// because we didn't take the time to find a bootloader that was arm64
// compatible so far.
func Bootable(bootable *bool) bool {
	if bootable == nil {
		return runtime.GOARCH == "amd64"
	}
	return *bootable
}
