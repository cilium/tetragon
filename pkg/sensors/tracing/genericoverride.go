// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"path"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

type OverrideType string

const (
	OverrideTypeKProbe  = "kprobe"
	OverrideTypeFmodRet = "fmod_ret"
)

var overrideProgMap map[string]*program.Program

func getOverrideProgMapKey(overrideType OverrideType, attachFunc string) string {
	return string(overrideType) + attachFunc
}

func createFmodRetOverrideProg(attachFunc string) *program.Program {
	overrideProg := program.Builder(
		"bpf_generic_override.o",
		attachFunc,
		"fmod_ret/security_task_prctl",
		"fmod_ret/"+attachFunc,
		"generic_fmod_ret")

	overrideProg.PinPath = path.Join("__override__", "fmod_ret", attachFunc)

	overrideTasksMap := program.MapBuilder("override_tasks", overrideProg)
	overrideTasksMap.PinPath = path.Join("__override__", "override_tasks")
	overrideTasksMap.SetMaxEntries(overrideMapMaxEntries)

	return overrideProg
}

func createKProbeOverrideProg(attachFunc string) *program.Program {
	overrideProg := program.Builder(
		"bpf_generic_override.o",
		attachFunc,
		"kprobe/generic_kprobe_override",
		"kprobe/"+attachFunc,
		"generic_kprobe_override")

	overrideProg.PinPath = path.Join("__override__", "kprobe", attachFunc)

	overrideTasksMap := program.MapBuilder("override_tasks", overrideProg)
	overrideTasksMap.PinPath = path.Join("__override__", "override_tasks")
	overrideTasksMap.SetMaxEntries(overrideMapMaxEntries)

	return overrideProg
}

func getOverrideProg(overrideType OverrideType, attachFunc string) (*program.Program, *program.Map) {
	var overrideProg *program.Program
	var ok bool

	if overrideProgMap == nil {
		overrideProgMap = make(map[string]*program.Program)
	}

	key := getOverrideProgMapKey(overrideType, attachFunc)

	if overrideProg, ok = overrideProgMap[key]; !ok {

		switch overrideType {
		case OverrideTypeKProbe:
			overrideProg = createKProbeOverrideProg(attachFunc)
		case OverrideTypeFmodRet:
			overrideProg = createFmodRetOverrideProg(attachFunc)
		}

		overrideProgMap[key] = overrideProg
	}

	logger.GetLogger().Info("Getting a new override prog", "prog", overrideProg, "map", overrideProg.PinMap["override_tasks"])

	return overrideProg, overrideProg.PinMap["override_tasks"]
}

func deleteOverrideProg(overrideType OverrideType, attachFunc string) {
	var prog *program.Program
	var ok bool

	key := getOverrideProgMapKey(overrideType, attachFunc)

	if overrideProgMap == nil {
		return
	}
	if prog, ok = overrideProgMap[key]; !ok {
		return
	}
	if !prog.LoadState.IsLoaded() {
		delete(overrideProgMap, key)
	}
}
