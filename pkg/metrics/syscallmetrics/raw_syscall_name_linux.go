// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package syscallmetrics

import (
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/syscallinfo"
)

func rawSyscallName(tp *tetragon.ProcessTracepoint) string {
	sysID := int64(-1)
	var sysABI string
	for _, x := range tp.Args {
		if x, ok := x.GetArg().(*tetragon.KprobeArgument_SyscallId); ok {
			sysID = int64(x.SyscallId.Id)
			sysABI = x.SyscallId.Abi
			break
		}
	}
	if sysID == -1 {
		return ""
	}
	name, err := syscallinfo.GetSyscallName(sysABI, int(sysID))
	if err != nil {
		return ""
	}
	return name
}
