// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package program

import (
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf"

	"github.com/cilium/tetragon/pkg/logger"
)

// The idea of LoadedCollection is to keep loaded programs and maps
// from ebpf.Collection to be used later for 'TestLoad*' tests to
// verify loaded programs and maps.
//
// We can't just iterate all existing programs and maps for 2 reasons:
//   - we could race with others loading bpf programs
//   - we get limited name (16 bytes), which we usually cross with
//     our names for maps and programs
//
// The process of loading LoadedCollection is following:
//
//   - ebpf collection is loaded
//
//     coll := NewCollectionWithOptions
//
//   - copy all programs/maps from ebpf collection
//
//     copyLoadedCollection(lc, coll)
//
//   - collection is removed and only 'used' programs and maps stay loaded
//     so we filter out unused programs/maps with (based on their IDs)
//
//     load.LC = filterLoadedCollection(lc)
//
// This way we have only programs/maps realted to our test and with
// original long names.
//
// All this is happening only when program.KeepCollection is set true,
// so it's enabled only for testing code.

var (
	KeepCollection bool
)

type LoadedMap struct {
	ID ebpf.MapID
}

type LoadedProgram struct {
	ID     ebpf.ProgramID
	MapIDs []ebpf.MapID
	Type   ebpf.ProgramType
}

type LoadedCollection struct {
	Programs map[string]*LoadedProgram
	Maps     map[string]*LoadedMap
}

func newLoadedCollection() *LoadedCollection {
	lc := &LoadedCollection{}
	lc.Maps = map[string]*LoadedMap{}
	lc.Programs = map[string]*LoadedProgram{}
	return lc
}

func printLoadedCollection(str string, lc *LoadedCollection) {
	logger.GetLogger().Debug(fmt.Sprintf("Programs (%s):", str))
	for name, lp := range lc.Programs {
		logger.GetLogger().Debug(fmt.Sprintf(" - %d: %s - %v", lp.ID, name, lp.MapIDs))
	}
	logger.GetLogger().Debug(fmt.Sprintf("Maps (%s):", str))
	for name, lm := range lc.Maps {
		logger.GetLogger().Debug(fmt.Sprintf(" - %d: %s", lm.ID, name))
	}
}

func copyLoadedCollection(coll *ebpf.Collection) (*LoadedCollection, error) {
	if coll == nil {
		return nil, errors.New("failed to get collection")
	}
	lc := newLoadedCollection()
	// copy all loaded maps
	for name, m := range coll.Maps {
		info, err := m.Info()
		if err != nil {
			return nil, err
		}
		id, ok := info.ID()
		if !ok {
			return nil, errors.New("failed to get id")
		}
		lm := &LoadedMap{id}
		lc.Maps[name] = lm
	}
	// copy all loaded programs with assigned map ids
	for name, p := range coll.Programs {
		info, err := p.Info()
		if err != nil {
			return nil, err
		}
		id, ok := info.ID()
		if !ok {
			return nil, errors.New("failed to get id")
		}
		mapIDs, ok := info.MapIDs()

		lp := &LoadedProgram{ID: id}
		if ok {
			lp.MapIDs = mapIDs
		}
		lp.Type = p.Type()
		lc.Programs[name] = lp
	}
	return lc, nil
}

// Gets all the programs/maps and removes any non existent ones
// from passed collection
func filterLoadedCollection(lc *LoadedCollection) *LoadedCollection {
	ret := newLoadedCollection()

	// filter out non existing programs
	lastProg := ebpf.ProgramID(0)
	for {
		next, err := ebpf.ProgramGetNextID(lastProg)
		if errors.Is(err, os.ErrNotExist) {
			break
		}
		for name, lp := range lc.Programs {
			if lp.ID == next {
				ret.Programs[name] = lp
			}
		}
		lastProg = next
	}

	// filter out non existing maps
	lastMap := ebpf.MapID(0)
	for {
		next, err := ebpf.MapGetNextID(lastMap)
		if errors.Is(err, os.ErrNotExist) {
			break
		}
		for name, lm := range lc.Maps {
			if lm.ID == next {
				ret.Maps[name] = lm
			}
		}
		lastMap = next
	}
	for _, lp := range lc.Programs {
		var mapIDs []ebpf.MapID

		for _, mi := range lp.MapIDs {
			for _, lm := range lc.Maps {
				if lm.ID == mi {
					mapIDs = append(mapIDs, mi)
					break
				}
			}
		}
		lp.MapIDs = mapIDs
	}
	return ret
}
