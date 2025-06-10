// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package mbset

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/sensors/exec/execvemap"
)

const (
	MapName       = "tg_mbset_map"
	RemovalName   = "tg_mbset_removal"
	ExecveMapName = "execve_map"
	InvalidID     = ^uint32(0)
	MaxIDs        = 64 // this value should correspond to the number of bits we can fit in mbset_t
)

type UpdateExecveMap interface {
	MBSetBitClear(bit uint32, pids []uint32) error
}

type bitSet = uint64

func openMap(name string) (*ebpf.Map, error) {
	fname := filepath.Join(bpf.MapPrefixPath(), name)
	ret, err := ebpf.LoadPinnedMap(fname, &ebpf.LoadPinOptions{})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", fname, err)
	}
	return ret, nil
}

type state struct {
	mu  sync.Mutex
	ids map[uint32]struct{}
}

func newState() (*state, error) {
	if update == nil {
		return nil, errors.New("UpdateExecveMap not initialized\n")
	}
	return &state{
		ids: make(map[uint32]struct{}),
	}, nil
}

// AllocID allocates a new ID
func (s *state) AllocID() (uint32, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for id := range uint32(MaxIDs) {
		if _, ok := s.ids[id]; !ok {
			s.ids[id] = struct{}{}
			return id, nil
		}
	}
	return 0, errors.New("cannot allocate new id")
}

func (s *state) RemoveID(id uint32, paths [][processapi.BINARY_PATH_MAX_LEN]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// There's limited number of mbset IDs (64) that we can use,
	// so we need to release them when the policy is removed.
	//
	// We need to:
	// 1) set ID in tg_mbset_removal map
	// 2) clean up mbset_map and unset ID bit from all its records
	// 3) clean up execve_map and unset ID bit from all its binary records
	// 4) remove id from the state map
	// 5) unset ID in tg_mbset_removal map

	mbsetMap, err := openMap(MapName)
	if err != nil {
		return fmt.Errorf("failed to open mbset map: %w", err)
	}
	defer mbsetMap.Close()

	mbsetRem, err := openMap(RemovalName)
	if err != nil {
		return fmt.Errorf("failed to open mbset removal map: %w", err)
	}
	defer mbsetRem.Close()

	hash, err := openMap(ExecveMapName)
	if err != nil {
		return fmt.Errorf("failed to open execve_map hash map: %w", err)
	}
	defer hash.Close()

	bit := uint64(1) << id

	// 1) Set ID in tg_mbset_removal map
	if err := mbsetRem.Update(uint32(0), uint64(bit), 0); err != nil {
		return fmt.Errorf("failed to update mbset removal: %w", err)
	}

	// 2) Clean up mbset_map
	for _, path := range paths {
		var val bitSet

		err := mbsetMap.Lookup(path, &val)
		if err != nil {
			return fmt.Errorf("failed to lookup mbset map: %w", err)
		}

		val &= ^bit

		if val != 0 {
			if err := mbsetMap.Update(path, val, ebpf.UpdateExist); err != nil {
				return fmt.Errorf("failed to update mbset map: %w", err)
			}
		} else {
			if err := mbsetMap.Delete(path); err != nil {
				return fmt.Errorf("failed to remove mbset map: %w", err)
			}
		}
	}

	// 3) Clean up execve_map_val
	var (
		key  execvemap.ExecveKey
		val  execvemap.ExecveValue
		pids []uint32
	)

	iter := hash.Iterate()
	for iter.Next(&key, &val) {
		if val.Binary.MBSet&bit != 0 {
			pids = append(pids, key.Pid)
		}
	}

	if err := update.MBSetBitClear(id, pids); err != nil {
		return err
	}

	// 4) Unset ID in tg_mbset_removal map
	if err := mbsetRem.Update(uint32(0), uint64(0), 0); err != nil {
		return fmt.Errorf("failed to update mbset removal: %w", err)
	}

	// 5) Remove id from the state map
	if _, ok := s.ids[id]; !ok {
		return fmt.Errorf("cannot find id %d", id)
	}
	delete(s.ids, id)

	return nil
}

// UpadteMap updates the map for a given id and its paths
// (NB: only an In operator for the paths is supported)
func (s *state) UpdateMap(id uint32, paths [][processapi.BINARY_PATH_MAX_LEN]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id == InvalidID {
		return errors.New("invalid id")
	} else if id >= MaxIDs {
		return errors.New("unexpected id")
	}

	mbsetMap, err := openMap(MapName)
	if err != nil {
		return fmt.Errorf("failed to open mbset map: %w", err)
	}
	defer mbsetMap.Close()

	bit := uint64(1) << id
	for _, path := range paths {
		var val bitSet
		var uflags ebpf.MapUpdateFlags
		err := mbsetMap.Lookup(path, &val)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			val = bit
			uflags = ebpf.UpdateNoExist
		} else if err != nil {
			return fmt.Errorf("failed to lookup mbset map: %w", err)
		} else {
			val |= bit
			uflags = ebpf.UpdateExist
		}

		if err := mbsetMap.Update(path, val, uflags); err != nil {
			return fmt.Errorf("failed to update mbset map: %w", err)
		}
	}

	return nil
}

var (
	glbSt          *state
	glbErr         error // nolint:errname
	setGlobalState sync.Once
	update         UpdateExecveMap
)

func getState() (*state, error) {
	setGlobalState.Do(func() {
		glbSt, glbErr = newState()
	})

	return glbSt, glbErr
}

func AllocID() (uint32, error) {
	s, err := getState()
	if err != nil {
		return InvalidID, err
	}
	return s.AllocID()
}

func RemoveID(id uint32, paths [][processapi.BINARY_PATH_MAX_LEN]byte) error {
	s, err := getState()
	if err != nil {
		return err
	}
	return s.RemoveID(id, paths)
}

func UpdateMap(id uint32, paths [][processapi.BINARY_PATH_MAX_LEN]byte) error {
	s, err := getState()
	if err != nil {
		return err
	}
	return s.UpdateMap(id, paths)
}

func SetMBSetUpdater(upd UpdateExecveMap) {
	update = upd
}
