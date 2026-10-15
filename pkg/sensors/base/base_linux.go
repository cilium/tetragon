// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package base

import (
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/strutils"
)

// BPFProcScanEnabled returns true if the startup process scan is done by the
// proc_scan BPF program instead of reading procfs.
func BPFProcScanEnabled() bool {
	return config.EnableV61Progs() && bpf.HasTaskIterAllProcs()
}

func GetDefaultPrograms() []*program.Program {
	progs := []*program.Program{
		Exit,
		Fork,
		Execve,
		ExecveBprmCommit,
		ExecveMapUpdate,
	}
	if BPFProcScanEnabled() {
		progs = append(progs, BpfProcScan)
	}
	return progs
}

func GetDefaultMaps() []*program.Map {
	maps := []*program.Map{
		ExecveMap,
		ExecveJoinMap,
		ExecveStats,
		ExecveJoinMapStats,
		ExecveMapUpdateData,
		TCPMonMap,
		TetragonConfMap,
		StatsMap,
		MatchBinariesSetMap,
		MatchBinariesGenMap,
		ErrMetricsMap,
	}

	if !config.EnableLargeProgs() {
		maps = append(maps, ExecveTailCallsMap)
	}

	if option.Config.ParentsMapEnabled {
		maps = append(maps, ParentBinariesMap)
	}
	if BPFProcScanEnabled() {
		maps = append(maps, BpfProcScanMap)
	}
	if config.EnableV511Progs() {
		maps = append(maps, RodataConfigMap)
	}

	// The BPF ring buffer is available from v5.8, but rather than add another set of
	// kernel-version-specific objects, let's set the gate at v5.11 as we already have
	// objects for that version number.
	if config.EnableV511Progs() && !option.Config.UsePerfRingBuffer {
		rbSize := config.GetRBSize()
		RingBufEvents.SetMaxEntries(rbSize)
		logger.GetLogger().Info("BPF ring buffer size (bytes)", "total", strutils.SizeWithSuffix(rbSize))
		maps = append(maps, RingBufEvents)
	}
	return maps

}
