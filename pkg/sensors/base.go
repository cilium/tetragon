// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package sensors

import "github.com/cilium/tetragon/pkg/kernels"

var (
	Execve = ProgramBuilder(
		"bpf_execve_event.o",
		"sched/sched_process_exec",
		"tracepoint/sys_execve",
		"event_execve",
		"execve",
	)

	ExecveV53 = ProgramBuilder(
		"bpf_execve_event_v53.o",
		"sched/sched_process_exec",
		"tracepoint/sys_execve",
		"event_execve",
		"execve",
	)

	Exit = ProgramBuilder(
		"bpf_exit.o",
		"sched/sched_process_exit",
		"tracepoint/sys_exit",
		"event_exit",
		"tracepoint",
	)

	Fork = ProgramBuilder(
		"bpf_fork.o",
		"wake_up_new_task",
		"kprobe/wake_up_new_task",
		"kprobe_pid_clear",
		"kprobe",
	)

	/* Event Ring map */
	TCPMonMap    = MapBuilder("tcpmon_map", Execve)
	TCPMonMapV53 = MapBuilder("tcpmon_map", ExecveV53)

	/* Networking and Process Monitoring maps */
	ExecveMap    = MapBuilder("execve_map", Execve)
	ExecveMapV53 = MapBuilder("execve_map", ExecveV53)

	/* Policy maps populated from base programs */
	NamesMap    = MapBuilder("names_map", Execve)
	NamesMapV53 = MapBuilder("names_map", ExecveV53)

	/* Internal statistics for debugging */
	ExecveStats    = MapBuilder("execve_map_stats", Execve)
	ExecveStatsV53 = MapBuilder("execve_map_stats", ExecveV53)
)

func GetExecveMap() *Map {
	if kernels.EnableLargeProgs() {
		return ExecveMapV53
	}
	return ExecveMap
}
