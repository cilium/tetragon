// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"github.com/cilium/tetragon/pkg/cgtracker"
	"github.com/cilium/tetragon/pkg/idtable"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

const (
	userMap = 1 << iota
	sensorMap
)

type mapEnabledFn[HASMAP any] func([]idtable.EntryID, HASMAP) bool

type mapProcess[HASMAP any] func(*program.Map, []idtable.EntryID, HASMAP)

type mapDep[HASMAP any] struct {
	enabled mapEnabledFn[HASMAP]
	process mapProcess[HASMAP]
	flags   uint8
}

type mapDeps[HASMAP any] map[string]mapDep[HASMAP]

func (m mapDeps[HASMAP]) depsToMaps(load *program.Program, multiIDs []idtable.EntryID, has HASMAP) []*program.Map {
	var maps []*program.Map
	for mapName, entry := range m {
		if entry.enabled != nil && !entry.enabled(multiIDs, has) {
			continue
		}
		var m *program.Map
		switch {
		case entry.flags&userMap != 0:
			m = program.MapUser(mapName, load)
		case entry.flags&sensorMap != 0:
			m = program.MapBuilderSensor(mapName, load)
		default:
			m = program.MapBuilderProgram(mapName, load)
		}
		if entry.process != nil {
			entry.process(m, multiIDs, has)
		}
		maps = append(maps, m)
	}
	return maps
}

func (m mapDeps[HASMAP]) withCGtrackerMap() mapDeps[HASMAP] {
	m[cgtracker.MapName] = mapDep[HASMAP]{
		enabled: func(_ []idtable.EntryID, _ HASMAP) bool {
			return option.Config.EnableCgTrackerID
		},
		flags: userMap,
	}
	return m
}

func (m mapDeps[HASMAP]) withConfigMap() mapDeps[HASMAP] {
	m["config_map"] = mapDep[HASMAP]{
		process: func(p *program.Map, multiIDs []idtable.EntryID, _ HASMAP) {
			if multiIDs != nil {
				p.SetMaxEntries(len(multiIDs))
			}
		},
	}
	return m
}

func (m mapDeps[HASMAP]) withFilterMap() mapDeps[HASMAP] {
	m["filter_map"] = mapDep[HASMAP]{
		process: func(p *program.Map, multiIDs []idtable.EntryID, _ HASMAP) {
			if multiIDs != nil {
				p.SetMaxEntries(len(multiIDs))
			}
		},
	}
	return m
}

func (m mapDeps[HASMAP]) withRetprobeMap() mapDeps[HASMAP] {
	m["retprobe_map"] = mapDep[HASMAP]{
		flags: sensorMap,
	}
	return m
}
