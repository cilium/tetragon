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

	Exit = program.Builder(
		"bpf_exit.o",
		"sched/sched_process_exit",
		"tracepoint/sys_exit",
		"event_exit",
		"tracepoint",
	)

	CgroupMkdir = program.Builder(
		"bpf_cgroup_mkdir.o",
		"cgroup/cgroup_mkdir",
		"raw_tracepoint/cgroup_mkdir",
		"tg_tp_cgrp_mkdir",
		"raw_tracepoint",
	)

	CgroupRmdir = program.Builder(
		"bpf_cgroup_rmdir.o",
		"cgroup/cgroup_rmdir",
		"raw_tracepoint/cgroup_rmdir",
		"tg_tp_cgrp_rmdir",
		"raw_tracepoint",
	)

	CgroupRelease = program.Builder(
		"bpf_cgroup_release.o",
		"cgroup/cgroup_release",
		"raw_tracepoint/cgroup_release",
		"tg_tp_cgrp_release",
		"raw_tracepoint",
	)

	CgroupAttachTask = program.Builder(
		"bpf_cgroup_attach_task.o",
		"cgroup/cgroup_attach_task",
		"raw_tracepoint/cgroup_attach_task",
		"tg_tp_cgrp_attach_task",
		"raw_tracepoint",
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

	/* Networking and Process Monitoring maps */
	ExecveMap    = program.MapBuilder("execve_map", Execve)
	ExecveMapV53 = program.MapBuilder("execve_map", ExecveV53)

	ExecveTailCallsMap    = program.MapBuilderPin("execve_calls", "execve_calls", Execve)
	ExecveTailCallsMapV53 = program.MapBuilderPin("execve_calls", "execve_calls", ExecveV53)

	/* Cgroup tracking maps */
	CgroupsTrackingMap    = program.MapBuilder("tg_cgrps_tracking_map", CgroupAttachTask)
	CgroupsTrackingMapV53 = program.MapBuilder("tg_cgrps_tracking_map", CgroupAttachTask)

	/* Policy maps populated from base programs */
	NamesMap    = program.MapBuilder("names_map", Execve)
	NamesMapV53 = program.MapBuilder("names_map", ExecveV53)

	/* Tetragon runtime configuration */
	TetragonConfMap    = program.MapBuilder("tg_conf_map", Execve)
	TetragonConfMapV53 = program.MapBuilder("tg_conf_map", ExecveV53)

	/* Internal statistics for debugging */
	ExecveStats    = program.MapBuilder("execve_map_stats", Execve)
	ExecveStatsV53 = program.MapBuilder("execve_map_stats", ExecveV53)
)

func GetExecveMap() *program.Map {
	if kernels.EnableLargeProgs() {
		return ExecveMapV53
	}
	return ExecveMap
}

func GetExecveMapStats() *program.Map {
	if kernels.EnableLargeProgs() {
		return ExecveStatsV53
	}
	return ExecveStats
}

func GetCgroupsTrackingMap() *program.Map {
	if kernels.EnableLargeProgs() {
		return CgroupsTrackingMapV53
	}
	return CgroupsTrackingMap
}

func GetTetragonConfMap() *program.Map {
	if kernels.EnableLargeProgs() {
		return TetragonConfMapV53
	}
	return TetragonConfMap
}

func GetDefaultPrograms() []*program.Program {
	progs := []*program.Program{
		Exit,
		Fork,
		CgroupAttachTask,
		CgroupMkdir,
		CgroupRmdir,
		CgroupRelease,
	}
	if kernels.EnableLargeProgs() {
		progs = append(progs, ExecveV53)
	} else {
		progs = append(progs, Execve)
	}
	return progs
}

func GetDefaultMaps() []*program.Map {
	maps := []*program.Map{}

	if kernels.EnableLargeProgs() {
		maps = append(maps,
			ExecveMapV53,
			ExecveStatsV53,
			ExecveTailCallsMapV53,
			NamesMapV53,
			TCPMonMapV53,
			TetragonConfMapV53,
			CgroupsTrackingMapV53,
		)
	} else {
		maps = append(maps,
			ExecveMap,
			ExecveStats,
			ExecveTailCallsMap,
			NamesMap,
			TCPMonMap,
			TetragonConfMap,
			CgroupsTrackingMap,
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
