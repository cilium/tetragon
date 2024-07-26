// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package base

import (
	"log"
	"sync"

	"github.com/cilium/tetragon/pkg/ksyms"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/exec/config"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

const (
	CgroupRateMaxEntries = 32768 // this value could be fine tuned
)

var (
	Execve = program.Builder(
		config.ExecObj(),
		"sched/sched_process_exec",
		"tracepoint/sys_execve",
		"event_execve",
		"execve",
	)

	ExecveBprmCommit = program.Builder(
		"bpf_execve_bprm_commit_creds.o",
		"security_bprm_committing_creds",
		"kprobe/security_bprm_committing_creds",
		"tg_kp_bprm_committing_creds",
		"kprobe",
	)

	Exit = program.Builder(
		"bpf_exit.o",
		"acct_process",
		"kprobe/acct_process",
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

	CgroupRmdir = program.Builder(
		"bpf_cgroup.o",
		"cgroup/cgroup_rmdir",
		"raw_tracepoint/cgroup_rmdir",
		"tg_cgroup_rmdir",
		"raw_tracepoint",
	)

	/* Event Ring map */
	TCPMonMap = program.MapBuilder("tcpmon_map", Execve)
	/* Networking and Process Monitoring maps */
	ExecveMap          = program.MapBuilder("execve_map", Execve)
	ExecveTailCallsMap = program.MapBuilderPin("execve_calls", "execve_calls", Execve)

	ExecveJoinMap = program.MapBuilder("tg_execve_joined_info_map", ExecveBprmCommit)

	/* Tetragon runtime configuration */
	TetragonConfMap = program.MapBuilder("tg_conf_map", Execve)

	/* Internal statistics for debugging */
	ExecveStats        = program.MapBuilder("execve_map_stats", Execve)
	ExecveJoinMapStats = program.MapBuilder("tg_execve_joined_info_map_stats", ExecveBprmCommit)
	StatsMap           = program.MapBuilder("tg_stats_map", Execve)

	/* Cgroup rate data, attached to execve sensor */
	CgroupRateMap        = program.MapBuilder("cgroup_rate_map", Execve, Exit, Fork, CgroupRmdir)
	CgroupRateOptionsMap = program.MapBuilder("cgroup_rate_options_map", Execve)

	HasCgroupRate bool

	sensor = sensors.Sensor{
		Name: "__base__",
	}
	sensorInit sync.Once

	sensorTest = sensors.Sensor{
		Name: "__base__",
	}
	sensorTestInit sync.Once
)

func setupExitProgram() {
	ks, err := ksyms.KernelSymbols()
	if err == nil {
		has_acct_process := ks.IsAvailable("acct_process")
		has_disassociate_ctty := ks.IsAvailable("disassociate_ctty")

		/* Preffer acct_process over disassociate_ctty */
		if has_acct_process {
			Exit.Attach = "acct_process"
			Exit.Label = "kprobe/acct_process"
		} else if has_disassociate_ctty {
			Exit.Attach = "disassociate_ctty"
			Exit.Label = "kprobe/disassociate_ctty"
		} else {
			log.Fatal("Failed to detect exit probe symbol.")
		}
	}
	logger.GetLogger().Infof("Exit probe on %s", Exit.Attach)
}

func GetExecveMap() *program.Map {
	return ExecveMap
}

func GetExecveMapStats() *program.Map {
	return ExecveStats
}

func GetTetragonConfMap() *program.Map {
	return TetragonConfMap
}

func GetDefaultPrograms(cgroupRate bool) []*program.Program {
	progs := []*program.Program{
		Exit,
		Fork,
		Execve,
		ExecveBprmCommit,
	}
	if cgroupRate {
		progs = append(progs, CgroupRmdir)
	}
	return progs
}

func GetDefaultMaps(cgroupRate bool) []*program.Map {
	maps := []*program.Map{
		ExecveMap,
		ExecveJoinMap,
		ExecveStats,
		ExecveJoinMapStats,
		ExecveTailCallsMap,
		TCPMonMap,
		TetragonConfMap,
		StatsMap,
	}
	if cgroupRate {
		maps = append(maps, CgroupRateMap, CgroupRateOptionsMap)
	}
	return maps

}

// GetInitialSensor returns the base sensor
func GetInitialSensor() *sensors.Sensor {
	sensorInit.Do(func() {
		setupExitProgram()
		sensor.Progs = GetDefaultPrograms(option.CgroupRateEnabled())
		sensor.Maps = GetDefaultMaps(option.CgroupRateEnabled())
	})
	return &sensor
}

func GetInitialSensorTest() *sensors.Sensor {
	sensorTestInit.Do(func() {
		setupExitProgram()
		sensorTest.Progs = GetDefaultPrograms(true)
		sensorTest.Maps = GetDefaultMaps(true)
	})
	return &sensorTest
}

func ConfigCgroupRate(opts *option.CgroupRate) {
	if opts.Events == 0 || opts.Interval == 0 {
		return
	}

	HasCgroupRate = true
	CgroupRateMap.SetMaxEntries(CgroupRateMaxEntries)
}
