// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package base

import (
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

	ExecveV60 = program.Builder(
		"bpf_execve_event_v60.o",
		"sched/sched_process_exec",
		"tracepoint/sys_execve",
		"event_execve",
		"execve",
	)

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
	TCPMonMapV60 = program.MapBuilder("tcpmon_map", ExecveV60)

	/* Networking and Process Monitoring maps */
	ExecveMap    = program.MapBuilder("execve_map", Execve)
	ExecveMapV53 = program.MapBuilder("execve_map", ExecveV53)
	ExecveMapV60 = program.MapBuilder("execve_map", ExecveV60)

	ExecveTailCallsMap    = program.MapBuilderPin("execve_calls", "execve_calls", Execve)
	ExecveTailCallsMapV53 = program.MapBuilderPin("execve_calls", "execve_calls", ExecveV53)
	ExecveTailCallsMapV60 = program.MapBuilderPin("execve_calls", "execve_calls", ExecveV60)

	/* Policy maps populated from base programs */
	NamesMap    = program.MapBuilder("names_map", Execve)
	NamesMapV53 = program.MapBuilder("names_map", ExecveV53)
	NamesMapV60 = program.MapBuilder("names_map", ExecveV60)

	/* Tetragon runtime configuration */
	TetragonConfMap    = program.MapBuilder("tg_conf_map", Execve)
	TetragonConfMapV53 = program.MapBuilder("tg_conf_map", ExecveV53)
	TetragonConfMapV60 = program.MapBuilder("tg_conf_map", ExecveV60)

	/* Internal statistics for debugging */
	ExecveStats    = program.MapBuilder("execve_map_stats", Execve)
	ExecveStatsV53 = program.MapBuilder("execve_map_stats", ExecveV53)
	ExecveStatsV60 = program.MapBuilder("execve_map_stats", ExecveV60)
)

func GetExecveMap() *program.Map {
	if kernels.EnableV60Progs() {
		return ExecveMapV60
	}
	if kernels.EnableLargeProgs() {
		return ExecveMapV53
	}
	return ExecveMap
}

func GetExecveMapStats() *program.Map {
	if kernels.EnableV60Progs() {
		return ExecveStatsV60
	}
	if kernels.EnableLargeProgs() {
		return ExecveStatsV53
	}
	return ExecveStats
}

func GetTetragonConfMap() *program.Map {
	if kernels.EnableV60Progs() {
		return TetragonConfMapV60
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
	if kernels.EnableV60Progs() {
		progs = append(progs, ExecveV60)
	} else if kernels.EnableLargeProgs() {
		progs = append(progs, ExecveV53)
	} else {
		progs = append(progs, Execve)
	}
	return progs
}

func GetDefaultMaps() []*program.Map {
	maps := []*program.Map{}

	if kernels.EnableV60Progs() {
		maps = append(maps,
			ExecveMapV60,
			ExecveStatsV60,
			ExecveTailCallsMapV60,
			NamesMapV60,
			TCPMonMapV60,
			TetragonConfMapV60,
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
