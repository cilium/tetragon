// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package encoder

import (
	"fmt"
	"strconv"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/syscallinfo"
)

func rawSyscallEnter(tp *tetragon.ProcessTracepoint) string {
	sysID := int64(-1)
	defaultABI, err := syscallinfo.DefaultABI()
	if err != nil {
		return "unknown"
	}
	abi := defaultABI
	// we assume that the syscall id is in the first argument
	if len(tp.Args) > 0 && tp.Args[0] != nil {
		if x, ok := tp.Args[0].GetArg().(*tetragon.KprobeArgument_LongArg); ok {
			sysID = x.LongArg
		} else if x, ok := tp.Args[0].GetArg().(*tetragon.KprobeArgument_SyscallId); ok {
			sysID = int64(x.SyscallId.Id)
			abi = x.SyscallId.Abi
		}
	}

	sysName := "unknown"
	if name, _ := syscallinfo.GetSyscallName(abi, int(sysID)); name != "" {
		sysName = name
		if abi != defaultABI {
			sysName = fmt.Sprintf("%s/%s", abi, sysName)
		}
		sysArgs, ok := syscallinfo.GetSyscallArgs(sysName)
		if ok {
			sysName += "("
			for j, arg := range sysArgs {
				if j > 0 {
					sysName += ", "
				}
				i := j + 1

				argVal := "?"
				isPtr := false
				if len(tp.Args) > i && tp.Args[i] != nil {
					if x, ok := tp.Args[i].GetArg().(*tetragon.KprobeArgument_SizeArg); ok {
						argVal_ := x.SizeArg
						if len(arg.Type) > 0 && arg.Type[len(arg.Type)-1] == '*' {
							isPtr = true
							argVal = fmt.Sprintf("0x%x", argVal_)
						} else {
							argVal = strconv.FormatUint(argVal_, 10)
						}
					}
				}
				if isPtr {
					sysName += fmt.Sprintf("%s%s=%s", arg.Type, arg.Name, argVal)
				} else {
					sysName += fmt.Sprintf("%s %s=%s", arg.Type, arg.Name, argVal)
				}
			}
			sysName += ")"
		}
	}
	return sysName
}
