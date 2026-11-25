// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package mbset

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/sensors/exec/execvemap"
)

type testMaps struct {
	mbset  *ebpf.Map
	execve *ebpf.Map
}

// newTestState returns a state that works on private (unpinned) copies of
// tg_mbset_map and execve_map, so this needs to run privileged.
func newTestState(t *testing.T) (*state, *testMaps) {
	t.Helper()

	mbsetMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    processapi.BINARY_PATH_MAX_LEN,
		ValueSize:  8,
		MaxEntries: 16,
	})
	require.NoError(t, err)
	t.Cleanup(func() { mbsetMap.Close() })

	execveMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    uint32(binary.Size(execvemap.ExecveKey{})),
		ValueSize:  uint32(binary.Size(execvemap.ExecveValue{})),
		MaxEntries: 16,
	})
	require.NoError(t, err)
	t.Cleanup(func() { execveMap.Close() })

	s, err := newState()
	require.NoError(t, err)
	s.openMap = func(name string) (*ebpf.Map, error) {
		// callers close what they get, so hand out clones
		switch name {
		case MapName:
			return mbsetMap.Clone()
		case ExecveMapName:
			return execveMap.Clone()
		}
		return nil, errors.New("unexpected map " + name)
	}
	return s, &testMaps{mbset: mbsetMap, execve: execveMap}
}

func binPath(s string) [processapi.BINARY_PATH_MAX_LEN]byte {
	var p [processapi.BINARY_PATH_MAX_LEN]byte
	copy(p[:], s)
	return p
}

func (m *testMaps) addProcess(t *testing.T, pid uint32, mbset uint64) {
	t.Helper()
	var val execvemap.ExecveValue
	val.Binary.MBSet = mbset
	require.NoError(t, m.execve.Put(execvemap.ExecveKey{Pid: pid}, &val))
}

func (m *testMaps) delProcess(t *testing.T, pid uint32) {
	t.Helper()
	require.NoError(t, m.execve.Delete(execvemap.ExecveKey{Pid: pid}))
}

// fillIDs allocates all remaining IDs
func fillIDs(t *testing.T, s *state) {
	t.Helper()
	for len(s.ids) < MaxIDs {
		_, err := s.AllocID()
		require.NoError(t, err)
	}
}

func TestRemoveIDNoUpdaterNoProcesses(t *testing.T) {
	require.Nil(t, update)
	s, m := newTestState(t)

	id, err := s.AllocID()
	require.NoError(t, err)

	cat := binPath("/usr/bin/cat")
	require.NoError(t, m.mbset.Put(cat, uint64(1)<<id))
	// some other process with an unrelated bit
	m.addProcess(t, 100, uint64(1)<<(id+1))

	require.NoError(t, s.RemoveID(id, [][processapi.BINARY_PATH_MAX_LEN]byte{cat, cat}))

	var val uint64
	require.ErrorIs(t, m.mbset.Lookup(cat, &val), ebpf.ErrKeyNotExist)
	require.NotContains(t, s.ids, id)
	require.Empty(t, s.stale)

	id2, err := s.AllocID()
	require.NoError(t, err)
	require.Equal(t, id, id2)
}

func TestRemoveIDNoUpdaterKeepsIDInUse(t *testing.T) {
	require.Nil(t, update)
	s, m := newTestState(t)

	id, err := s.AllocID()
	require.NoError(t, err)
	other, err := s.AllocID()
	require.NoError(t, err)

	cat := binPath("/usr/bin/cat")
	require.NoError(t, m.mbset.Put(cat, uint64(1)<<id|uint64(1)<<other))
	m.addProcess(t, 100, uint64(1)<<id)

	require.Error(t, s.RemoveID(id, [][processapi.BINARY_PATH_MAX_LEN]byte{cat}))

	// mbset map is cleaned up even though the ID is kept
	var val uint64
	require.NoError(t, m.mbset.Lookup(cat, &val))
	require.Equal(t, uint64(1)<<other, val)

	require.Contains(t, s.ids, id)
	require.Contains(t, s.stale, id)

	// the ID must not be handed out while pid 100 still has its bit
	fillIDs(t, s)
	_, err = s.AllocID()
	require.Error(t, err)
	require.Contains(t, s.stale, id)

	// once the process is gone the ID gets reclaimed
	m.delProcess(t, 100)
	id2, err := s.AllocID()
	require.NoError(t, err)
	require.Equal(t, id, id2)
	require.Empty(t, s.stale)
}

func TestAllocIDReclaimsOnlyUnusedStaleIDs(t *testing.T) {
	require.Nil(t, update)
	s, m := newTestState(t)

	a, err := s.AllocID()
	require.NoError(t, err)
	b, err := s.AllocID()
	require.NoError(t, err)

	m.addProcess(t, 100, uint64(1)<<a)
	m.addProcess(t, 200, uint64(1)<<b)
	require.Error(t, s.RemoveID(a, nil))
	require.Error(t, s.RemoveID(b, nil))

	fillIDs(t, s)
	m.delProcess(t, 200)

	id, err := s.AllocID()
	require.NoError(t, err)
	require.Equal(t, b, id)
	require.Contains(t, s.stale, a)
	require.NotContains(t, s.stale, b)

	_, err = s.AllocID()
	require.Error(t, err)
}

func TestReleaseID(t *testing.T) {
	s, err := newState()
	require.NoError(t, err)

	id, err := s.AllocID()
	require.NoError(t, err)
	s.ReleaseID(id)

	id2, err := s.AllocID()
	require.NoError(t, err)
	require.Equal(t, id, id2)
}
