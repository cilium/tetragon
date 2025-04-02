// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package base

import (
	"github.com/cilium/tetragon/pkg/sensors/program"
)

var (
	CreateProcess = program.Builder(
		"process_monitor.sys",
		"process",
		"ProcessMonitor",
		"process::program",
		"windows",
	).SetPolicy(basePolicy)

	ProcessRingBufMap = program.MapBuilder("process_ringbuf", CreateProcess)
	ProcessPidMap     = program.MapBuilder("process_map", CreateProcess)
	ProcessCmdMap     = program.MapBuilder("command_map", CreateProcess)
)

func GetDefaultPrograms() []*program.Program {
	progs := []*program.Program{
		CreateProcess,
	}
	return progs
}

func GetDefaultMaps() []*program.Map {
	maps := []*program.Map{
		ProcessRingBufMap,
		ProcessCmdMap,
		ProcessPidMap,
	}
	return maps

}
