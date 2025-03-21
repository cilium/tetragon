// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package kernels

import (
	"fmt"
	"syscall"
	"unsafe"
)

func GetKernelVersion(kernelVersion, procfs string) (int, string, error) {
	var version int
	var verStr string

	if kernelVersion != "" {
		version = int(KernelStringToNumeric(kernelVersion))
		verStr = kernelVersion
	} else {

		var mod = syscall.NewLazyDLL("ntdll.dll")
		var proc = mod.NewProc("RtlGetVersion")

		var osVersionInfo = struct {
			dwOSVersionInfoSize uint32
			dwMajorVersion      uint32
			dwMinorVersion      uint32
			dwBuildNumber       uint32
			dwPlatformId        uint32
			szCSDVersion        [128]uint16
		}{
			dwOSVersionInfoSize: 284,
		}

		ret, _, _ := proc.Call(uintptr(unsafe.Pointer(&osVersionInfo)))
		if ret != 0 {
			return 0, "", fmt.Errorf("error calling rtlgetversion %s, %s", kernelVersion, procfs)
		}

		verStr = fmt.Sprintf("%d.%d.%d",
			osVersionInfo.dwMajorVersion,
			osVersionInfo.dwMinorVersion,
			osVersionInfo.dwBuildNumber)

		version = int(osVersionInfo.dwMajorVersion<<16) + int(osVersionInfo.dwMinorVersion<<8) + int(osVersionInfo.dwBuildNumber)
	}
	return version, verStr, nil
}

func GenericKprobeObjs() (string, string) {
	return "", ""
}

func MinKernelVersion(kernel string) bool {

	runningVersion, _, _ := GetKernelVersion("", "")

	minVersion := int(KernelStringToNumeric(kernel))

	return minVersion <= runningVersion
}
