// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package policyfilter

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/option"
)

const (
	MapName = "policy_filter_maps"
)

// map operations used by policyfilter.

// PfMap is a simple wrapper for ebpf.Map so that we can write methods for it
type PfMap struct {
	*ebpf.Map
}

// newMap returns a new policy filter map.
func newPfMap() (PfMap, error) {
	// use the generic kprobe program, to find the policy filter map spec
	objName, _ := kernels.GenericKprobeObjs()
	objPath := path.Join(option.Config.HubbleLib, objName)
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return PfMap{}, fmt.Errorf("loading spec for %s failed: %w", objPath, err)
	}
	policyMapSpec, ok := spec.Maps[MapName]
	if !ok {
		return PfMap{}, fmt.Errorf("%s not found in %s", MapName, objPath)
	}

	// bpf-side sets max_entries to 1. Later kernels (5.10) can deal with
	// inserting a different size of inner-map, but for older kernels, we
	// fix the spec here.
	policyMapSpec.InnerMap.MaxEntries = polMapSize

	ret, err := ebpf.NewMap(policyMapSpec)
	if err != nil {
		return PfMap{}, err
	}

	mapDir := bpf.MapPrefixPath()
	pinPath := filepath.Join(mapDir, MapName)
	os.Remove(pinPath)
	os.Mkdir(mapDir, os.ModeDir)
	err = ret.Pin(pinPath)
	if err != nil {
		ret.Close()
		return PfMap{}, fmt.Errorf("failed to pin policy filter map in %s: %w", pinPath, err)
	}

	return PfMap{ret}, err
}

// release closes the policy filter bpf map and remove (unpin) the bpffs file
func (m PfMap) release() error {
	if err := m.Close(); err != nil {
		return err
	}

	// nolint:revive // ignore "if-return: redundant if just return error" for clarity
	if err := m.Unpin(); err != nil {
		return err
	}

	return nil
}

// addPolicyMap adds and initializes a new policy map
func (m PfMap) newPolicyMap(polID PolicyID, cgIDs []CgroupID) (polMap, error) {
	name := fmt.Sprintf("policy_%d_map", polID)
	innerSpec := &ebpf.MapSpec{
		Name:       name,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(CgroupID(0))),
		ValueSize:  uint32(1),
		MaxEntries: uint32(polMapSize),
	}

	inner, err := ebpf.NewMap(innerSpec)
	if err != nil {
		return polMap{}, fmt.Errorf("failed to create policy (id=%d) map: %w", polID, err)
	}

	// update inner map with ids
	ret := polMap{inner}
	if err := ret.addCgroupIDs(cgIDs); err != nil {
		ret.Close()
		return polMap{}, fmt.Errorf("failed to update policy (id=%d): %w", polID, err)
	}

	// update outer map
	// NB(kkourt): use UpdateNoExist because we expect only a single policy with a given id
	if err := m.Update(polID, uint32(ret.FD()), ebpf.UpdateNoExist); err != nil {
		ret.Close()
		return polMap{}, fmt.Errorf("failed to insert inner policy (id=%d) map: %w", polID, err)
	}

	return ret, nil
}

func (m PfMap) readAll() (map[PolicyID]map[CgroupID]struct{}, error) {

	readInner := func(id uint32) (map[CgroupID]struct{}, error) {
		inMap, err := ebpf.NewMapFromID(ebpf.MapID(id))
		if err != nil {
			return nil, fmt.Errorf("error opening inner map: %w", err)
		}
		defer inMap.Close()

		inIter := inMap.Iterate()
		var key CgroupID
		var val uint8

		ret := map[CgroupID]struct{}{}
		for inIter.Next(&key, &val) {
			ret[key] = struct{}{}
		}

		if err := inIter.Err(); err != nil {
			return nil, fmt.Errorf("error iterating inner map: %w", err)
		}

		return ret, nil

	}

	ret := make(map[PolicyID]map[CgroupID]struct{})
	var key PolicyID
	var id uint32

	iter := m.Iterate()
	for iter.Next(&key, &id) {
		cgids, err := readInner(id)
		if err != nil {
			return nil, err
		}
		ret[key] = cgids
	}

	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("error iterating outer map: %w", err)
	}

	return ret, nil
}

// polMap is a simple wrapper for ebpf.Map so that we can write methods for it
type polMap struct {
	*ebpf.Map
}

type batchError struct {
	// SuccCount is the number of successful operations
	SuccCount int
	err       error
}

func (e *batchError) Error() string {
	return e.err.Error()
}

func (e *batchError) Unwrap() error {
	return e.err
}

// addCgroupIDs add cgroups ids to the policy map
// todo: use batch operations when supported
func (m polMap) addCgroupIDs(cgIDs []CgroupID) error {
	var zero uint8
	for i, cgID := range cgIDs {
		if err := m.Update(&cgID, zero, ebpf.UpdateAny); err != nil {
			return &batchError{
				SuccCount: i,
				err:       fmt.Errorf("failed to update policy map (cgroup id: %d): %w", cgID, err),
			}
		}
	}

	return nil
}

// addCgroupIDs delete cgroups ids from the policy map
// todo: use batch operations when supported
func (m polMap) delCgroupIDs(cgIDs []CgroupID) error {
	for i, cgID := range cgIDs {
		if err := m.Delete(&cgID); err != nil {
			return &batchError{
				SuccCount: i,
				err:       fmt.Errorf("failed to delete items from policy map (cgroup id: %d): %w", cgID, err),
			}
		}
	}

	return nil
}

func OpenMap(fname string) (PfMap, error) {
	m, err := ebpf.LoadPinnedMap(fname, &ebpf.LoadPinOptions{
		ReadOnly: true,
	})

	if err != nil {
		return PfMap{}, err
	}

	return PfMap{m}, err
}

func (m PfMap) Dump() (map[PolicyID]map[CgroupID]struct{}, error) {
	return m.readAll()
}
