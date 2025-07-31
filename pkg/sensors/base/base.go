// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package base

import (
	"fmt"
	"log"
	"sync"
	"testing"
	"unsafe"

	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/errmetrics"
	"github.com/cilium/tetragon/pkg/execvemapupdater"
	"github.com/cilium/tetragon/pkg/ksyms"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/mbset"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/exec/execvemap"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/strutils"
)

const (
	execveMapMaxEntries = 32768
	RingBufMapName      = "tg_rb_events"
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

	ExecveMapUpdate = program.Builder(
		config.ExecUpdateObj(),
		"seccomp",
		"seccomp",
		"execve_map_update",
		"seccomp",
	).SetPolicy(basePolicy)

	ExecveBprmCommit = program.Builder(
		"bpf_execve_bprm_commit_creds.o",
		"security_bprm_committing_creds",
		"kprobe/security_bprm_committing_creds",
		"tg_kp_bprm_committing_creds",
		"kprobe",
	).SetPolicy(basePolicy)

	Exit = program.Builder(
		config.ExitObj(),
		"acct_process",
		"kprobe/acct_process",
		"event_exit",
		"kprobe",
	).SetPolicy(basePolicy)

	Fork = program.Builder(
		config.ForkObj(),
		"wake_up_new_task",
		"kprobe/wake_up_new_task",
		"kprobe_pid_clear",
		"kprobe",
	).SetPolicy(basePolicy)

	/* Event Ring map */
	TCPMonMap     = program.MapBuilder("tcpmon_map", Execve)
	RingBufEvents = program.MapBuilder(RingBufMapName, Execve, Exit, Fork)
	/* Networking and Process Monitoring maps */
	ExecveMap           = program.MapBuilder("execve_map", Execve, Exit, Fork, ExecveBprmCommit, ExecveMapUpdate)
	ExecveTailCallsMap  = program.MapBuilderProgram("execve_calls", Execve)
	ExecveMapUpdateData = program.MapBuilder("execve_map_update_data", ExecveMapUpdate)

	ExecveJoinMap = program.MapBuilder("tg_execve_joined_info_map", ExecveBprmCommit)

	/* Tetragon runtime configuration */
	TetragonConfMap = program.MapBuilder("tg_conf_map", Execve)

	/* Internal statistics for debugging */
	ExecveStats        = program.MapBuilder("execve_map_stats", Execve)
	ExecveJoinMapStats = program.MapBuilder("tg_execve_joined_info_map_stats", ExecveBprmCommit)
	StatsMap           = program.MapBuilder("tg_stats_map", Execve)

	MatchBinariesSetMap = program.MapBuilder(mbset.MapName, Execve)
	MatchBinariesGenMap = program.MapBuilder(mbset.GenName, Execve)

	ErrMetricsMap = program.MapBuilder(errmetrics.MapName, Execve)
)

func parseExecveMapSize(str string) (int, error) {
	// set entries based on size
	size, err := strutils.ParseSize(str)
	if err != nil {
		return 0, err
	}
	val := size / int(unsafe.Sizeof(execvemap.ExecveValue{}))
	return val, nil
}

func GetExecveEntries(configEntries int, configSize string) int {
	// Setup execve_map max entries
	if configEntries != 0 && len(configSize) != 0 {
		log.Fatal("Both ExecveMapEntries and ExecveMapSize set, confused..")
	}

	var (
		entries int
		err     error
	)

	if configEntries != 0 {
		entries = configEntries
	} else if len(configSize) != 0 {
		if entries, err = parseExecveMapSize(configSize); err != nil {
			log.Fatal("Failed to parse ExecveMapSize value")
		}
	} else {
		entries = execveMapMaxEntries
	}

	return entries
}

func setupSensor() {
	// exit program function
	ks, err := ksyms.KernelSymbols()
	if err == nil {
		hasAcctProcess := ks.IsAvailable("acct_process")
		hasDisassociateCtty := ks.IsAvailable("disassociate_ctty")

		/* Preffer acct_process over disassociate_ctty */
		if hasAcctProcess {
			Exit.Attach = "acct_process"
			Exit.Label = "kprobe/acct_process"
		} else if hasDisassociateCtty {
			Exit.Attach = "disassociate_ctty"
			Exit.Label = "kprobe/disassociate_ctty"
		} else {
			log.Fatal("Failed to detect exit probe symbol.")
		}
	}
	logger.GetLogger().Info("Exit probe on " + Exit.Attach)

	entries := GetExecveEntries(option.Config.ExecveMapEntries, option.Config.ExecveMapSize)
	ExecveMap.SetMaxEntries(entries)

	logger.GetLogger().Info(fmt.Sprintf("Set execve_map entries %d", entries),
		"size", strutils.SizeWithSuffix(entries*int(unsafe.Sizeof(execvemap.ExecveValue{}))))

	if option.Config.EnableProcessEnvironmentVariables {
		Execve.RewriteConstants["ENV_VARS_ENABLED"] = uint8(1)
	}
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

func initBaseSensor() *sensors.Sensor {
	sensor := sensors.Sensor{
		Name: basePolicy,
	}
	setupSensor()
	if config.EnableLargeProgs() {
		mbset.SetMBSetUpdater(&execvemapupdater.ExecveMapUpdater{
			Load: ExecveMapUpdate,
			Map:  ExecveMapUpdateData,
		})
	}
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
