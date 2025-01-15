// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package base

import (
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"unsafe"

	"github.com/cilium/tetragon/pkg/errmetrics"
	"github.com/cilium/tetragon/pkg/ksyms"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/mbset"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/exec/config"
	"github.com/cilium/tetragon/pkg/sensors/exec/execvemap"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/strutils"
)

const (
	execveMapMaxEntries = 32768
)

var (
	basePolicy = "__base__"

	Execve = program.Builder(
		config.ExecObj(),
		"sched/sched_process_exec",
		"tracepoint/sys_execve",
		"event_execve",
		"execve",
	).SetPolicy(basePolicy)

	ExecveBprmCommit = program.Builder(
		"bpf_execve_bprm_commit_creds.o",
		"security_bprm_committing_creds",
		"kprobe/security_bprm_committing_creds",
		"tg_kp_bprm_committing_creds",
		"kprobe",
	).SetPolicy(basePolicy)

	Exit = program.Builder(
		"bpf_exit.o",
		"acct_process",
		"kprobe/acct_process",
		"event_exit",
		"kprobe",
	).SetPolicy(basePolicy)

	Fork = program.Builder(
		"bpf_fork.o",
		"wake_up_new_task",
		"kprobe/wake_up_new_task",
		"kprobe_pid_clear",
		"kprobe",
	).SetPolicy(basePolicy)

	/* Event Ring map */
	TCPMonMap = program.MapBuilder("tcpmon_map", Execve)
	/* Networking and Process Monitoring maps */
	ExecveMap          = program.MapBuilder("execve_map", Execve, Exit, Fork, ExecveBprmCommit)
	ExecveTailCallsMap = program.MapBuilderProgram("execve_calls", Execve)

	ExecveJoinMap = program.MapBuilder("tg_execve_joined_info_map", ExecveBprmCommit)

	/* Tetragon runtime configuration */
	TetragonConfMap = program.MapBuilder("tg_conf_map", Execve)

	/* Internal statistics for debugging */
	ExecveStats        = program.MapBuilder("execve_map_stats", Execve)
	ExecveJoinMapStats = program.MapBuilder("tg_execve_joined_info_map_stats", ExecveBprmCommit)
	StatsMap           = program.MapBuilder("tg_stats_map", Execve)

	MatchBinariesSetMap = program.MapBuilder(mbset.MapName, Execve)

	ErrMetricsMap = program.MapBuilder(errmetrics.MapName, Execve)
)

func readThreadsMax(path string) (int64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	str := strings.TrimRight(string(data), "\n")
	return strconv.ParseInt(str, 10, 32)
}

func setupExecveMap() {
	entry := int(unsafe.Sizeof(execvemap.ExecveValue{}))

	get := func(str string) int {
		// default value
		if str == "" {
			return execveMapMaxEntries
		}
		// pure number of entries
		if val, err := strconv.Atoi(str); err == nil {
			return val
		}
		// follow threads-max entries
		if str == "max" {
			if val, err := readThreadsMax("/proc/sys/kernel/threads-max"); err == nil {
				return int(val)
			}
			logger.GetLogger().Warn("Failed to read /proc/sys/kernel/threads-max file, falling back to default")
			return execveMapMaxEntries
		}
		// set entries based on size
		size, err := strutils.ParseSize(str)
		if err != nil {
			logger.GetLogger().Warn("Failed to parse --execve-map-max value, falling back to default")
			return execveMapMaxEntries
		}
		val := size / entry
		return val
	}

	entries := get(option.Config.ExecveMapEntries)
	ExecveMap.SetMaxEntries(entries)

	logger.GetLogger().
		WithField("size", strutils.SizeWithSuffix(entries*entry)).
		WithField("config", option.Config.ExecveMapEntries).
		Infof("Set execve_map entries %d", entries)

}

func setupSensor() {
	// exit program function
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

	setupExecveMap()
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

func initBaseSensor() *sensors.Sensor {
	sensor := sensors.Sensor{
		Name: basePolicy,
	}
	setupSensor()
	sensor.Progs = GetDefaultPrograms()
	sensor.Maps = GetDefaultMaps()
	return ApplyExtensions(&sensor)
}

func initBaseSensorFn() func(tb testing.TB) *sensors.Sensor {
	var (
		s *sensors.Sensor
		m sync.Mutex
	)
	return func(tb testing.TB) *sensors.Sensor {
		m.Lock()
		defer m.Unlock()
		if s == nil {
			s = initBaseSensor()
			tb.Cleanup(func() {
				tb.Logf("cleanup: unloading base sensor")
				s.Unload(true)
				s = nil
			})
		}
		return s
	}
}

var (
	// GetInitialSensor returns the base sensor
	GetInitialSensor     = sync.OnceValue(initBaseSensor)
	GetInitialSensorTest = initBaseSensorFn()
)
