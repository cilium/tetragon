// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package base

import (
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

var (
	Execve = program.Builder(
		"bpf_execve_event.o",
		"sched/sched_process_exec",
		"tracepoint/sys_execve",
		"event_execve",
		"execve",
	)

	ExecveV53 = program.Builder(
		"bpf_execve_event_v53.o",
		"sched/sched_process_exec",
		"tracepoint/sys_execve",
		"event_execve",
		"execve",
	)

	ExecveBTF = program.Builder(
		"bpf_execve_event_btftp.o",
		"tp_btf/sched_process_exec",
		"tp_btf/sched_process_exec",
		"event_execve",
		"execve",
	).SetProgName("event_execve")

	Exit = program.Builder(
		"bpf_exit.o",
		"sched/sched_process_exit",
		"tracepoint/sys_exit",
		"event_exit",
		"tracepoint",
	)

	Fork = program.Builder(
		"bpf_fork.o",
		"wake_up_new_task",
		"kprobe/wake_up_new_task",
		"kprobe_pid_clear",
		"kprobe",
	)

	/* Event Ring map */
	TCPMonMap    = program.MapBuilder("tcpmon_map", Execve)
	TCPMonMapV53 = program.MapBuilder("tcpmon_map", ExecveV53)
	TCPMonMapBTF = program.MapBuilder("tcpmon_map", ExecveBTF)

	/* Networking and Process Monitoring maps */
	ExecveMap    = program.MapBuilder("execve_map", Execve)
	ExecveMapV53 = program.MapBuilder("execve_map", ExecveV53)
	ExecveMapBTF = program.MapBuilder("execve_map", ExecveBTF)

	ExecveTailCallsMap    = program.MapBuilderPin("execve_calls", "execve_calls", Execve)
	ExecveTailCallsMapV53 = program.MapBuilderPin("execve_calls", "execve_calls", ExecveV53)
	ExecveTailCallsMapBTF = program.MapBuilderPin("execve_calls", "execve_calls", ExecveBTF)

	/* Policy maps populated from base programs */
	NamesMap    = program.MapBuilder("names_map", Execve)
	NamesMapV53 = program.MapBuilder("names_map", ExecveV53)
	NamesMapBTF = program.MapBuilder("names_map", ExecveBTF)

	/* Tetragon runtime configuration */
	TetragonConfMap    = program.MapBuilder("tg_conf_map", Execve)
	TetragonConfMapV53 = program.MapBuilder("tg_conf_map", ExecveV53)
	TetragonConfMapBTF = program.MapBuilder("tg_conf_map", ExecveBTF)

	/* Internal statistics for debugging */
	ExecveStats    = program.MapBuilder("execve_map_stats", Execve)
	ExecveStatsV53 = program.MapBuilder("execve_map_stats", ExecveV53)
	ExecveStatsBTF = program.MapBuilder("execve_map_stats", ExecveBTF)
)

func GetExecveMap() *program.Map {
	if bpf.HasRawTpBtf() {
		return ExecveMapBTF
	}
	if kernels.EnableLargeProgs() {
		return ExecveMapV53
	}
	return ExecveMap
}

func GetExecveMapStats() *program.Map {
	if bpf.HasRawTpBtf() {
		return ExecveStatsBTF
	}
	if kernels.EnableLargeProgs() {
		return ExecveStatsV53
	}
	return ExecveStats
}

func GetTetragonConfMap() *program.Map {
	if bpf.HasRawTpBtf() {
		return TetragonConfMapBTF
	}
	if kernels.EnableLargeProgs() {
		return TetragonConfMapV53
	}
	return TetragonConfMap
}

func GetDefaultPrograms() []*program.Program {
	progs := []*program.Program{
		Exit,
		Fork,
	}
	if bpf.HasRawTpBtf() {
		progs = append(progs, ExecveBTF)
	} else if kernels.EnableLargeProgs() {
		progs = append(progs, ExecveV53)
	} else {
		progs = append(progs, Execve)
	}
	return progs
}

func GetDefaultMaps() []*program.Map {
	maps := []*program.Map{}

	if bpf.HasRawTpBtf() {
		maps = append(maps,
			ExecveMapBTF,
			ExecveStatsBTF,
			ExecveTailCallsMapBTF,
			NamesMapBTF,
			TCPMonMapBTF,
		)
	} else if kernels.EnableLargeProgs() {
		maps = append(maps,
			ExecveMapV53,
			ExecveStatsV53,
			ExecveTailCallsMapV53,
			NamesMapV53,
			TCPMonMapV53,
			TetragonConfMapV53,
		)
	} else {
		maps = append(maps,
			ExecveMap,
			ExecveStats,
			ExecveTailCallsMap,
			NamesMap,
			TCPMonMap,
			TetragonConfMap,
		)
	}
	return maps

}

// GetInitialSensor returns the base sensor
func GetInitialSensor() *sensors.Sensor {
	return &sensors.Sensor{
		Name:  "__base__",
		Progs: GetDefaultPrograms(),
		Maps:  GetDefaultMaps(),
	}
}
