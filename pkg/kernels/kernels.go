// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package kernels

import (
	"io/ioutil"
	"strconv"
	"strings"

	"github.com/cilium/tetragon/pkg/option"

	"golang.org/x/sys/unix"
)

func KernelStringToNumeric(ver string) int64 {
	// vendors like to define kernel 4.14.128-foo but
	// everything after '-' is meaningless from BPF
	// side so toss it out.
	release := strings.Split(ver, "-")
	verStr := release[0]
	numeric := strings.TrimRight(verStr, "+")
	vers := strings.Split(numeric, ".")

	// Split out major, minor, and patch versions
	majorS := vers[0]
	minorS := ""
	if len(vers) >= 2 {
		minorS = vers[1]
	}
	patchS := ""
	if len(vers) >= 3 {
		patchS = vers[2]
	}

	// If we have no major version number, all is lost
	major, err := strconv.ParseInt(majorS, 10, 32)
	if err != nil {
		return 0
	}
	// Fall back to minor = 0 if we can't parse the minor version
	minor, err := strconv.ParseInt(minorS, 10, 32)
	if err != nil {
		minor = 0
	}
	// Fall back to patch = 0 if we can't parse the patch version
	patch, err := strconv.ParseInt(patchS, 10, 32)
	if err != nil {
		patch = 0
	}

	return ((major << 16) + (minor << 8) + patch)
}

func GetKernelVersion(kernelVersion, procfs string) (int, string, error) {
	var version int
	var verStr string

	if kernelVersion != "" {
		version = int(KernelStringToNumeric(kernelVersion))
		verStr = kernelVersion
	} else {
		if versionSig, err := ioutil.ReadFile(procfs + "/version_signature"); err == nil {
			versionStrings := strings.Fields(string(versionSig))
			version = int(KernelStringToNumeric(versionStrings[len(versionStrings)-1]))
			verStr = versionStrings[len(versionStrings)-1]
		} else {
			var uname unix.Utsname

			err := unix.Uname(&uname)
			if err != nil {
				verStr = "unknown"
				// On error default to bpf discovery which
				// will work in many cases, notable exception
				// is the cloud vendors and others that mangle
				// the kernel version string.
				return 0, verStr, nil
			}
			release := unix.ByteSliceToString(uname.Release[:])
			verStr = strings.Split(release, "-")[0]
			version = int(KernelStringToNumeric(release))
		}
	}
	return version, verStr, nil
}

func FixKernelVersion(version int) int {
	// Commit a256aac5 in linux-stable's 4.19.y branch broke userspace by setting version
	// sublevel to 255 no matter what. This broke kprobes on impacted 4.19 versions
	// (4.19.221 to 4.19.231). Patch sublevel to 255 to catch this case.
	if version&0xffff00 == 267008 {
		sublevel := version & 0xff
		if sublevel >= 221 && sublevel <= 231 {
			// Set sublevel to 255
			version |= 0xff
		}
	}
	return version
}

func MinKernelVersion(kernel string) bool {
	var uname unix.Utsname

	if err := unix.Uname(&uname); err != nil {
		return true
	}
	// vendors like to define kernel 4.14.128-foo but
	// everything after '-' is meaningless from BPF
	// side so toss it out.
	release := strings.TrimSuffix(
		strings.Split(unix.ByteSliceToString(uname.Release[:]), "-")[0],
		"+")

	runningVersion := int(KernelStringToNumeric(release))
	minVersion := int(KernelStringToNumeric(kernel))

	if minVersion <= runningVersion {
		return true
	}
	return false
}

func EnableLargeProgs() bool {
	if option.Config.ForceSmallProgs {
		return false
	}
	kernelVer, _, _ := GetKernelVersion(option.Config.KernelVersion, option.Config.ProcFS)
	return (int64(kernelVer) >= KernelStringToNumeric("5.3.0"))
}

func IsKernelVersionLessThan(version string) bool {
	kernelVer, _, _ := GetKernelVersion(option.Config.KernelVersion, option.Config.ProcFS)
	return (int64(kernelVer) < KernelStringToNumeric(version))
}
