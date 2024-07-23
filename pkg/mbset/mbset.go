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

type bitSet = uint64

func openMap() (*ebpf.Map, error) {
	fname := filepath.Join(bpf.MapPrefixPath(), MapName)
	ret, err := ebpf.LoadPinnedMap(fname, &ebpf.LoadPinOptions{})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", fname, err)
	}
	return ret, nil
}

type state struct {
	mu       sync.Mutex
	nextID   uint32
	mbsetMap *ebpf.Map
}

func newState() (*state, error) {
	m, err := openMap()
	if err != nil {
		return nil, fmt.Errorf("failed to open map: %w", err)
	}
	return &state{
		mbsetMap: m,
	}, nil
}

func (s *state) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mbsetMap.Close()
}

// AllocID allocates a new ID
func (s *state) AllocID() (uint32, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.nextID >= MaxIDs {
		return InvalidID, fmt.Errorf("cannot allocate new id")
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
		return fmt.Errorf("invalid id")
	} else if id >= MaxIDs {
		return fmt.Errorf("unexpected id")
	}

	bit := uint64(1) << id
	for _, path := range paths {
		var val bitSet
		var uflags ebpf.MapUpdateFlags
		err := s.mbsetMap.Lookup(path, &val)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			val = bit
			uflags = ebpf.UpdateNoExist
		} else if err != nil {
			return fmt.Errorf("failed to lookup mbset map: %w", err)
		} else {
			val |= bit
			uflags = ebpf.UpdateExist
		}

		if err := s.mbsetMap.Update(path, val, uflags); err != nil {
			return fmt.Errorf("failed to update mbset map: %w", err)
		}
	}

	return nil
}

var (
	glbSt          *state
	glbErr         error
	setGlobalState sync.Once
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
