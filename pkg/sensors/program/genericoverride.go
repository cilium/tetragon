// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package program

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"path"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/api/tracingapi"
	"github.com/cilium/tetragon/pkg/idtable"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/sensors/unloader"
)

const OverrideMapMaxEntries = 32768

type OverrideType string

const (
	OverrideTypeKProbe  = "kprobe"
	OverrideTypeFmodRet = "fmod_ret"
)

var (
	overrideProgMap map[string]*genericOverride
	overrideIDTable idtable.Table
)

type genericOverride struct {
	tableId idtable.EntryID
	prog    *Program
}

func (g *genericOverride) SetID(id idtable.EntryID) {
	g.tableId = id
}

func getOverrideProgMapKey(overrideType OverrideType, attachFunc string) string {
	return string(overrideType) + attachFunc
}

func createFmodRetOverrideProg(attachFunc string) *genericOverride {
	var ret genericOverride
	overrideIDTable.AddEntry(&ret)

	overrideProg := Builder(
		"bpf_generic_override.o",
		attachFunc,
		"fmod_ret/security_task_prctl",
		"fmod_ret/"+attachFunc,
		"generic_fmod_ret")

	overrideProg.PinPath = path.Join("__override__", "fmod_ret", attachFunc)
	overrideProg.unloaderOverride = &unloader.CustomUnloader{
		UnloadFunc: func(_ bool) error {
			return deleteOverrideProg(OverrideTypeFmodRet, attachFunc, &ret)
		},
	}

	overrideTasksMap := MapBuilder("override_tasks", overrideProg)
	overrideTasksMap.PinPath = path.Join("__override__", "override_tasks")
	overrideTasksMap.SetMaxEntries(OverrideMapMaxEntries)

	var configData bytes.Buffer
	binary.Write(&configData, binary.LittleEndian, &tracingapi.OverrideConfig{
		OverrideID: uint32(ret.tableId.ID),
	})
	config := &MapLoad{
		Name: "override_config_map",
		Load: func(m *ebpf.Map, _ string) error {
			return m.Update(uint32(0), configData.Bytes()[:], ebpf.UpdateAny)
		},
	}
	overrideProg.MapLoad = append(overrideProg.MapLoad, config)
	ret.prog = overrideProg
	return &ret
}

func createKProbeOverrideProg(attachFunc string) *genericOverride {
	var ret genericOverride
	overrideIDTable.AddEntry(&ret)

	overrideProg := Builder(
		"bpf_generic_override.o",
		attachFunc,
		"kprobe/generic_kprobe_override",
		"kprobe/"+attachFunc,
		"generic_kprobe_override")

	overrideProg.PinPath = path.Join("__override__", "kprobe", attachFunc)
	overrideProg.unloaderOverride = &unloader.CustomUnloader{
		UnloadFunc: func(_ bool) error {
			return deleteOverrideProg(OverrideTypeKProbe, attachFunc, &ret)
		},
	}

	overrideTasksMap := MapBuilder("override_tasks", overrideProg)
	overrideTasksMap.PinPath = path.Join("__override__", "override_tasks")
	overrideTasksMap.SetMaxEntries(OverrideMapMaxEntries)

	var configData bytes.Buffer
	binary.Write(&configData, binary.LittleEndian, &tracingapi.OverrideConfig{
		OverrideID: uint32(ret.tableId.ID),
	})
	config := &MapLoad{
		Name: "override_config_map",
		Load: func(m *ebpf.Map, _ string) error {
			return m.Update(uint32(0), configData.Bytes()[:], ebpf.UpdateAny)
		},
	}
	overrideProg.MapLoad = append(overrideProg.MapLoad, config)
	ret.prog = overrideProg

	return &ret
}

func GetOverrideProg(overrideType OverrideType, attachFunc string) (*Program, *Map, int) {
	var overrideProg *genericOverride
	var ok bool

	if overrideProgMap == nil {
		overrideProgMap = make(map[string]*genericOverride)
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

	prog := overrideProg.prog

	logger.GetLogger().Info("Getting a new override prog", "id", overrideProg.tableId.ID, "prog", prog, "map", prog.PinMap["override_tasks"])

	return prog, prog.PinMap["override_tasks"], overrideProg.tableId.ID
}

func deleteOverrideProg(overrideType OverrideType, attachFunc string, override *genericOverride) error {
	var err error
	var ok bool

	if overrideProgMap == nil {
		return errors.New("override program map is not initialized")
	}

	key := getOverrideProgMapKey(overrideType, attachFunc)

	if _, ok = overrideProgMap[key]; !ok {
		return errors.New("override program is not found")
	}
	delete(overrideProgMap, key)

	_, err = overrideIDTable.RemoveEntry(override.tableId)

	if err != nil {
		return fmt.Errorf("failed to remove entry: %w", err)
	}
	return nil
}
