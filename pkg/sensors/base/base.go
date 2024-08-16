// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package base

import (
	"log"
	"sync"

	"github.com/cilium/tetragon/pkg/ksyms"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/mbset"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/exec/config"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

const (
	cgroupRateMaxEntries = 32768 // this value could be fine tuned
)

var (
	basePolicy = "__base__"

	execveMap            *program.Map
	execveStats          *program.Map
	cgroupRateMap        *program.Map
	cgroupRateOptionsMap *program.Map
	tetragonConfMap      *program.Map

	sensor     = sensors.Sensor{}
	sensorTest = sensors.Sensor{}

	sensorInit     sync.Once
	sensorTestInit sync.Once
)

func GetExecveMap() *program.Map {
	return execveMap
}

func GetExecveMapStats() *program.Map {
	return execveStats
}

func GetTetragonConfMap() *program.Map {
	return tetragonConfMap
}

func GetCgroupRateMap() *program.Map {
	return cgroupRateMap
}

func GetCgroupRateOptionsMap() *program.Map {
	return cgroupRateOptionsMap
}

func createInitialSensor(cgroupRate bool) sensors.Sensor {
	var progs []*program.Program
	var maps []*program.Map

	execve := program.Builder(
		config.ExecObj(),
		"sched/sched_process_exec",
		"tracepoint/sys_execve",
		"event_execve",
		"execve",
	).SetPolicy(basePolicy)

	execveBprmCommit := program.Builder(
		"bpf_execve_bprm_commit_creds.o",
		"security_bprm_committing_creds",
		"kprobe/security_bprm_committing_creds",
		"tg_kp_bprm_committing_creds",
		"kprobe",
	).SetPolicy(basePolicy)

	exit := program.Builder(
		"bpf_exit.o",
		"acct_process",
		"kprobe/acct_process",
		"event_exit",
		"kprobe",
	).SetPolicy(basePolicy)

	fork := program.Builder(
		"bpf_fork.o",
		"wake_up_new_task",
		"kprobe/wake_up_new_task",
		"kprobe_pid_clear",
		"kprobe",
	).SetPolicy(basePolicy)

	setupExitProgram(exit)

	progs = append(progs, exit, fork, execve, execveBprmCommit)

	if cgroupRate {
		cgroupRmdir := program.Builder(
			"bpf_cgroup.o",
			"cgroup/cgroup_rmdir",
			"raw_tracepoint/cgroup_rmdir",
			"tg_cgroup_rmdir",
			"raw_tracepoint",
		).SetPolicy(basePolicy)

		progs = append(progs, cgroupRmdir)

		cgroupRateMap = program.MapBuilder("cgroup_rate_map", execve, exit, fork, cgroupRmdir)
		cgroupRateOptionsMap = program.MapBuilder("cgroup_rate_options_map", execve)

		maps = append(maps, cgroupRateMap, cgroupRateOptionsMap)
	}

	tcpMonMap := program.MapBuilder("tcpmon_map", exit, fork, execve)
	maps = append(maps, tcpMonMap)

	matchBinariesSetMap := program.MapBuilder(mbset.MapName, execve)
	maps = append(maps, matchBinariesSetMap)

	execveMap = program.MapBuilder("execve_map", execve)
	maps = append(maps, execveMap)

	execveTailCallsMap := program.MapBuilderPin("execve_calls", "execve_calls", execve)
	maps = append(maps, execveTailCallsMap)

	execve.SetTailCall("tracepoint", execveTailCallsMap)

	execveJoinMap := program.MapBuilder("tg_execve_joined_info_map", execveBprmCommit)
	maps = append(maps, execveJoinMap)

	tetragonConfMap = program.MapBuilder("tg_conf_map", execve)
	maps = append(maps, tetragonConfMap)

	execveStats = program.MapBuilder("execve_map_stats", execve)
	maps = append(maps, execveStats)

	execveJoinMapStats := program.MapBuilder("tg_execve_joined_info_map_stats", execveBprmCommit)
	maps = append(maps, execveJoinMapStats)

	statsMap := program.MapBuilder("tg_stats_map", execve)
	maps = append(maps, statsMap)

	return sensors.Sensor{
		Progs: progs,
		Maps:  maps,
		Name:  basePolicy,
	}
}

func setupExitProgram(exit *program.Program) {
	ks, err := ksyms.KernelSymbols()
	if err == nil {
		has_acct_process := ks.IsAvailable("acct_process")
		has_disassociate_ctty := ks.IsAvailable("disassociate_ctty")

		/* Preffer acct_process over disassociate_ctty */
		if has_acct_process {
			exit.Attach = "acct_process"
			exit.Label = "kprobe/acct_process"
		} else if has_disassociate_ctty {
			exit.Attach = "disassociate_ctty"
			exit.Label = "kprobe/disassociate_ctty"
		} else {
			log.Fatal("Failed to detect exit probe symbol.")
		}
	}
	logger.GetLogger().Infof("Exit probe on %s", exit.Attach)
}

// GetInitialSensor returns the base sensor
func GetInitialSensor() *sensors.Sensor {
	sensorInit.Do(func() {
		sensor = createInitialSensor(option.CgroupRateEnabled())
	})
	return &sensor
}

func GetInitialSensorTest() *sensors.Sensor {
	sensorTestInit.Do(func() {
		sensorTest = createInitialSensor(true)
	})
	return &sensorTest
}

func ConfigCgroupRate(opts *option.CgroupRate) {
	if opts.Events == 0 || opts.Interval == 0 {
		return
	}

	cgroupRateMap.SetMaxEntries(cgroupRateMaxEntries)
}
