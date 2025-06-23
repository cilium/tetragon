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
)

const (
	MapName   = "tg_mbset_map"
	InvalidID = ^uint32(0)
	MaxIDs    = 64 // this value should correspond to the number of bits we can fit in mbset_t
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
	mu     sync.Mutex
	nextID uint32
}

func newState() (*state, error) {
	if update == nil {
		return nil, errors.New("UpdateExecveMap not initialized\n")
	}
	return &state{}, nil
}

// AllocID allocates a new ID
func (s *state) AllocID() (uint32, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.nextID >= MaxIDs {
		return InvalidID, errors.New("cannot allocate new id")
	}
	ret := s.nextID
	s.nextID++
	return ret, nil
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
