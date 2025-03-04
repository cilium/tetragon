// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/cilium/tetragon/pkg/api/tracingapi"
	"github.com/cilium/tetragon/pkg/arch"
	"github.com/cilium/tetragon/pkg/syscallinfo"
)

// The code in this file deals with values found in syscall lists (type: "syscalls")
// We need the following type of information for the values:
//  - ID(): a system call id
//  - Symbol(): the kernel function symbol that implements the syscall

type SyscallVal string

// return syscall id for value
func (v SyscallVal) ID() (int, error) {
	abi, sc, err := parseSyscallValue(v)
	if err != nil {
		return -1, err
	}

	sc = strings.TrimPrefix(sc, "sys_")
	id, err := syscallinfo.SyscallID(sc, abi)
	if err != nil {
		return -1, fmt.Errorf("failed list '%s' cannot translate syscall '%s' to id: %w", v, sc, err)
	}
	if abi == "i386" || abi == "arm32" {
		id |= Is32Bit
	}
	return id, nil
}

func (v SyscallVal) Symbol() (string, error) {
	abi, sc, err := parseSyscallValue(v)
	if err != nil {
		return "", err
	}

	var prefix string
	switch abi {
	case "x64":
		prefix = "__x64_"
	case "arm64":
		prefix = "__arm64_"
	case "i386":
		prefix = "__ia32_"
	case "arm32":
		// NB: arm32 syscall implementations typically use the same function as the arm64
		// syscalls.
		prefix = "__arm64_"
	default:
		return "", fmt.Errorf("unexpected error, unknown ABI: '%s'", abi)
	}

	if strings.HasPrefix(sc, prefix) {
		return sc, nil
	}

	if strings.HasPrefix(sc, "sys_") {
		return prefix + sc, nil
	}

	return "", fmt.Errorf("invalid syscall list element '%s'", v)
}

func validateABI(xarg, abi string) error {
	switch xarg {
	case "":
		// no arch
		if abi != "x64" && abi != "i386" && abi != "arm64" && abi != "arm32" {
			return fmt.Errorf("invalid ABI: %s", abi)
		}
	case "amd64":
		if abi != "x64" && abi != "i386" {
			return fmt.Errorf("invalid ABI (%s) for arch (%s)", abi, xarg)
		}
	case "i386":
		if abi != "i386" {
			return fmt.Errorf("invalid ABI (%s) for arch (%s)", abi, xarg)
		}
	case "arm64":
		if abi != "arm64" && abi != "arm32" {
			return fmt.Errorf("invalid ABI (%s) for arch (%s)", abi, xarg)
		}
	}

	return nil
}

// returns abi, syscall id
func parseSyscall64Value(val uint64) tracingapi.MsgGenericSyscallID {
	abi32 := false
	if val&Is32Bit != 0 {
		abi32 = true
		val = val & (^uint64(Is32Bit))
	}

	abi := "unknown"
	switch a := runtime.GOARCH; a {
	case "amd64":
		if abi32 {
			abi = "i386"
		} else {
			abi = "x64"
		}
	case "arm64":
		if abi32 {
			abi = "arm32"
		} else {
			abi = "arm64"
		}
	}

	return tracingapi.MsgGenericSyscallID{
		ID:  uint32(val),
		ABI: abi,
	}
}

func parseSyscallValue(value SyscallVal) (abi string, name string, err error) {
	val := string(value)
	arr := strings.Split(string(val), "/")
	switch len(arr) {
	case 1:
		// Original version of this code tried to determine the abi by looking at the
		// prefix, so we maintain this behavior although it will not work for ARM32.
		var xarch string
		xarch, name = arch.CutSyscallPrefix(val)
		switch xarch {
		case "":
			abi, err = syscallinfo.DefaultABI()
		case "amd64":
			abi = "x64"
		case "i386":
			abi = "i386"
		case "arm64":
			abi = "arm64"
		}
		return

	case 2:
		xabi := arr[0]
		xarch, xname := arch.CutSyscallPrefix(arr[1])
		if err = validateABI(xarch, xabi); err != nil {
			return
		}
		abi = xabi
		name = xname

	default:
		err = fmt.Errorf("invalid syscall value: '%s'", value)
	}
	return
}
