// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package program

import (
	"path"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/sensors/unloader"
)

const OverrideMapMaxEntries = 32768

type OverrideType string

const (
	OverrideTypeKProbe  = "kprobe"
	OverrideTypeFmodRet = "fmod_ret"
)

var overrideProgMap map[string]*Program

func getOverrideProgMapKey(overrideType OverrideType, attachFunc string) string {
	return string(overrideType) + attachFunc
}

func createFmodRetOverrideProg(attachFunc string) *Program {
	overrideProg := Builder(
		"bpf_generic_override.o",
		attachFunc,
		"fmod_ret/security_task_prctl",
		"fmod_ret/"+attachFunc,
		"generic_fmod_ret")

	overrideProg.PinPath = path.Join("__override__", "fmod_ret", attachFunc)
	overrideProg.unloaderOverride = &unloader.CustomUnloader{
		UnloadFunc: func(_ bool) error {
			deleteOverrideProg(OverrideTypeKProbe, attachFunc)
			return nil
		},
	}

	overrideTasksMap := MapBuilder("override_tasks", overrideProg)
	overrideTasksMap.PinPath = path.Join("__override__", "override_tasks")
	overrideTasksMap.SetMaxEntries(OverrideMapMaxEntries)

	return overrideProg
}

func createKProbeOverrideProg(attachFunc string) *Program {
	overrideProg := Builder(
		"bpf_generic_override.o",
		attachFunc,
		"kprobe/generic_kprobe_override",
		"kprobe/"+attachFunc,
		"generic_kprobe_override")

	overrideProg.PinPath = path.Join("__override__", "kprobe", attachFunc)
	overrideProg.unloaderOverride = &unloader.CustomUnloader{
		UnloadFunc: func(_ bool) error {
			deleteOverrideProg(OverrideTypeKProbe, attachFunc)
			return nil
		},
	}

	overrideTasksMap := MapBuilder("override_tasks", overrideProg)
	overrideTasksMap.PinPath = path.Join("__override__", "override_tasks")
	overrideTasksMap.SetMaxEntries(OverrideMapMaxEntries)

	return overrideProg
}

func GetOverrideProg(overrideType OverrideType, attachFunc string) (*Program, *Map) {
	var overrideProg *Program
	var ok bool

	if overrideProgMap == nil {
		overrideProgMap = make(map[string]*Program)
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
	var prog *Program
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
