// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package syscallmetrics

import (
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/syscallinfo"
)

func rawSyscallName(tp *tetragon.ProcessTracepoint) string {
	sysID := int64(-1)
	if len(tp.Args) > 0 && tp.Args[0] != nil {
		if x, ok := tp.Args[0].GetArg().(*tetragon.KprobeArgument_LongArg); ok {
			sysID = x.LongArg
		}
	}
	if sysID == -1 {
		return ""
	}
	abi, err := syscallinfo.DefaultABI()
	if err != nil {
		return ""
	}
	name, err := syscallinfo.GetSyscallName(abi, int(sysID))
	if err != nil {
		return ""
	}
	return name
}
