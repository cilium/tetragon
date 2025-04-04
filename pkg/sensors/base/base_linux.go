// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package base

import (
	"github.com/cilium/tetragon/pkg/sensors/program"
)

func GetDefaultPrograms() []*program.Program {
	progs := []*program.Program{
		Exit,
		Fork,
		Execve,
		ExecveBprmCommit,
	}
	return progs
}

func GetDefaultMaps() []*program.Map {
	maps := []*program.Map{
		ExecveMap,
		ExecveJoinMap,
		ExecveStats,
		ExecveJoinMapStats,
		ExecveTailCallsMap,
		TCPMonMap,
		TetragonConfMap,
		StatsMap,
		MatchBinariesSetMap,
		ErrMetricsMap,
	}
	return maps

}
