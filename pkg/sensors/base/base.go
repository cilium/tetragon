// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package base

import (
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

var (
	Execve = func() *program.Program {
		return program.Builder(
			ExecObj(),
			"sched/sched_process_exec",
			"tracepoint/sys_execve",
			"event_execve",
			"execve",
		)
	}()

	Exit = program.Builder(
		"bpf_exit.o",
		"__put_task_struct",
		"kprobe/__put_task_struct",
		"event_exit",
		"kprobe",
	)

	Fork = program.Builder(
		"bpf_fork.o",
		"wake_up_new_task",
		"kprobe/wake_up_new_task",
		"kprobe_pid_clear",
		"kprobe",
	)

	/* Event Ring map */
	TCPMonMap = program.MapBuilder("tcpmon_map", Execve)
	/* Networking and Process Monitoring maps */
	ExecveMap          = program.MapBuilder("execve_map", Execve)
	ExecveTailCallsMap = program.MapBuilderPin("execve_calls", "execve_calls", Execve)

	/* Policy maps populated from base programs */
	NamesMap = program.MapBuilder("names_map", Execve)

	/* Tetragon runtime configuration */
	TetragonConfMap = program.MapBuilder("tg_conf_map", Execve)

	/* Internal statistics for debugging */
	ExecveStats = program.MapBuilder("execve_map_stats", Execve)
)

func GetExecveMap() *program.Map {
	return ExecveMap
}

func GetExecveMapStats() *program.Map {
	return ExecveStats
}

func GetTetragonConfMap() *program.Map {
	return TetragonConfMap
}

func GetDefaultPrograms() []*program.Program {
	progs := []*program.Program{
		Exit,
		Fork,
		Execve,
	}
	return progs
}

func GetDefaultMaps() []*program.Map {
	maps := []*program.Map{
		ExecveMap,
		ExecveStats,
		ExecveTailCallsMap,
		NamesMap,
		TCPMonMap,
		TetragonConfMap,
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

// ExecObj returns the exec object based on the kernel version
func ExecObj() string {
	if kernels.EnableV60Progs() {
		return "bpf_execve_event_v60.o"
	} else if kernels.EnableLargeProgs() {
		return "bpf_execve_event_v53.o"
	} else {
		return "bpf_execve_event.o"
	}
}
