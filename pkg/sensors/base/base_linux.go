// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package base

import (
	"math"
	"os"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/strutils"
)

func GetDefaultPrograms() []*program.Program {
	progs := []*program.Program{
		Exit,
		Fork,
		Execve,
		ExecveBprmCommit,
		ExecveMapUpdate,
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
		ExecveMapUpdateData,
		TCPMonMap,
		TetragonConfMap,
		StatsMap,
		MatchBinariesSetMap,
		MatchBinariesGenMap,
		ErrMetricsMap,
	}
	// The BPF ring buffer is available from v5.8, but rather than add another set of
	// kernel-version-specific objects, let's set the gate at v5.11 as we already have
	// objects for that version number.
	if config.EnableV511Progs() {
		RingBufEvents.SetMaxEntries(getRBSize())
		maps = append(maps, RingBufEvents)
	}
	return maps

}

func getRBSize() int {
	var size int

	if option.Config.RBSize == 0 && option.Config.RBSizeTotal == 0 {
		size = perCPUBufferBytes * bpf.GetNumPossibleCPUs()
	} else if option.Config.RBSize != 0 {
		size = option.Config.RBSize * bpf.GetNumPossibleCPUs()
	} else {
		size = option.Config.RBSizeTotal
	}

	pageSize := os.Getpagesize()
	nPages := size / pageSize

	// Round up to nearest power of two number of pages
	nPages = int(math.Pow(2, math.Ceil(math.Log2(float64(nPages)))))
	size = nPages * pageSize

	logger.GetLogger().Info("BPF ring buffer size (bytes)", "total", strutils.SizeWithSuffix(size))
	return size
}
