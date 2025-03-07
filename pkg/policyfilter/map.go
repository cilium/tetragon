// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package policyfilter

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/option"
)

const (
	MapName       = "policy_filter_maps"
	CgroupMapName = "policy_filter_cgroup_maps"
)

// map operations used by policyfilter.

// PfMap is a simple wrapper for ebpf.Map so that we can write methods for it
type PfMap struct {
	policyMap *ebpf.Map // policy_filter_maps
	cgroupMap *ebpf.Map // policy_filter_cgroup_maps
}

func openMap(spec *ebpf.CollectionSpec, mapName string, innerMaxEntries uint32) (*ebpf.Map, error) {
	policyMapSpec, ok := spec.Maps[mapName]
	if !ok {
		return nil, fmt.Errorf("%s not found in object file", mapName)
	}

	// bpf-side sets max_entries to 1. Later kernels (5.10) can deal with
	// inserting a different size of inner-map, but for older kernels, we
	// fix the spec here.
	policyMapSpec.InnerMap.MaxEntries = innerMaxEntries

	ret, err := ebpf.NewMap(policyMapSpec)
	if err != nil {
		return nil, err
	}

	mapDir := bpf.MapPrefixPath()
	pinPath := filepath.Join(mapDir, mapName)
	os.Remove(pinPath)
	os.Mkdir(mapDir, os.ModeDir)

	if err := ret.Pin(pinPath); err != nil {
		ret.Close()
		return nil, fmt.Errorf("failed to pin policy filter map in %s: %w", pinPath, err)
	}

	return ret, nil
}

// newMap returns a new policy filter map.
func newPfMap(enableCgroupMap bool) (PfMap, error) {
	// use the generic kprobe program, to find the policy filter map spec
	objName, _ := config.GenericKprobeObjs()
	objPath := path.Join(option.Config.HubbleLib, objName)
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return PfMap{}, fmt.Errorf("loading spec for %s failed: %w", objPath, err)
	}

	var ret PfMap
	if ret.policyMap, err = openMap(spec, MapName, polMapSize); err != nil {
		return PfMap{}, fmt.Errorf("opening map %s failed: %w", MapName, err)
	}

	if enableCgroupMap {
		if ret.cgroupMap, err = openMap(spec, CgroupMapName, polMaxPolicies); err != nil {
			releaseMap(ret.policyMap)
			return PfMap{}, fmt.Errorf("opening cgroup map %s failed: %w", MapName, err)
		}
	}

	return ret, nil
}

func releaseMap(m *ebpf.Map) error {
	// this may happen in the case where the cgroup map is not enabled
	if m == nil {
		return nil
	}

	if err := m.Close(); err != nil {
		return err
	}

	// nolint:revive // ignore "if-return: redundant if just return error" for clarity
	if err := m.Unpin(); err != nil {
		return err
	}

	return nil
}

// release closes the policy filter bpf map and remove (unpin) the bpffs file
func (m PfMap) release() error {
	return errors.Join(
		releaseMap(m.policyMap),
		releaseMap(m.cgroupMap),
	)
}

func (m polMap) addPolicyIDs(polID PolicyID, cgIDs []CgroupID) error {
	for _, cgID := range cgIDs {
		if err := addPolicyIDMapping(m.cgroupMap, polID, cgID); err != nil {
			return err
		}
	}
	return nil
}

func addPolicyIDMapping(m *ebpf.Map, polID PolicyID, cgID CgroupID) error {
	// cgroup map does not exist, so nothing to do here
	if m == nil {
		return nil
	}

	var id uint32
	err := m.Lookup(cgID, &id)
	if err == nil { // inner map exists
		inMap, err := ebpf.NewMapFromID(ebpf.MapID(id))
		if err != nil {
			return fmt.Errorf("error opening inner map: %w", err)
		}
		defer inMap.Close()

		var zero uint8
		if err := inMap.Update(polID, zero, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("error updating inner map: %w", err)
		}

		return nil
	}

	// inner map does not exist
	name := fmt.Sprintf("cgroup_%d_map", cgID)
	innerSpec := &ebpf.MapSpec{
		Name:       name,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(PolicyID(0))),
		ValueSize:  uint32(1),
		MaxEntries: uint32(polMaxPolicies),
	}

	inner, err := ebpf.NewMap(innerSpec)
	if err != nil {
		return fmt.Errorf("failed to create cgroup (id=%d) map: %w", cgID, err)
	}
	defer inner.Close()

	var zero uint8
	if err := inner.Update(polID, zero, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("error updating inner map: %w", err)
	}

	if err := m.Update(cgID, uint32(inner.FD()), ebpf.UpdateNoExist); err != nil {
		inner.Close()
		return fmt.Errorf("failed to insert inner policy (id=%d) map: %w", polID, err)
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
	ret := polMap{
		Inner:     inner,
		cgroupMap: m.cgroupMap,
	}
	if err := ret.addCgroupIDs(cgIDs); err != nil {
		ret.Inner.Close()
		return polMap{}, fmt.Errorf("failed to update policy (id=%d): %w", polID, err)
	}

	// update outer map
	// NB(kkourt): use UpdateNoExist because we expect only a single policy with a given id
	if err := m.policyMap.Update(polID, uint32(ret.Inner.FD()), ebpf.UpdateNoExist); err != nil {
		ret.Inner.Close()
		return polMap{}, fmt.Errorf("failed to insert inner policy (id=%d) map: %w", polID, err)
	}

	// update cgroup map
	for _, cgID := range cgIDs {
		if err := addPolicyIDMapping(m.cgroupMap, polID, cgID); err != nil {
			return polMap{}, fmt.Errorf("failed to update cgroup map: %w", err)
		}
	}

	return ret, nil
}

func getMapSize(m *ebpf.Map) (uint32, error) {
	var key uint32
	var val uint8
	var mapSize uint32

	inIter := m.Iterate()
	for inIter.Next(&key, &val) {
		mapSize++
	}

	if err := inIter.Err(); err != nil {
		return 0, fmt.Errorf("error iterating inner map: %w", err)
	}

	return mapSize, nil
}

func (m PfMap) deletePolicyIDInCgroupMap(polID PolicyID) error {
	// cgroup map does not exist, so nothing to do here
	if m.cgroupMap == nil {
		return nil
	}

	var key CgroupID
	var id uint32

	cgIDs := []CgroupID{}
	iter := m.cgroupMap.Iterate()
	for iter.Next(&key, &id) {
		inMap, err := ebpf.NewMapFromID(ebpf.MapID(id))
		if err != nil {
			return fmt.Errorf("error opening inner map: %w", err)
		}
		defer inMap.Close()

		// We don't know if this exists if this does not exist this
		// will return an error, but this is fine.
		inMap.Delete(polID)

		// now we need to check the size of the inner map
		// if this is 0 we should also remove the outer entry
		mapSize, err := getMapSize(inMap)
		if err != nil {
			return fmt.Errorf("error getting inner map size: %w", err)
		}
		if mapSize == 0 {
			cgIDs = append(cgIDs, key)
		}
	}

	if err := iter.Err(); err != nil {
		return fmt.Errorf("deletePolicyIDInCgroupMap: error iterating cgroup map: %w", err)
	}

	// delete empty outer maps
	for _, cgID := range cgIDs {
		if err := m.cgroupMap.Delete(cgID); err != nil {
			return fmt.Errorf("error deleting outer map entry: %w", err)
		}
	}

	return nil
}

type PfMapDump struct {
	Policy map[PolicyID]map[CgroupID]struct{}
	Cgroup map[CgroupID]map[PolicyID]struct{}
}

func readAll[K PolicyID | CgroupID, V PolicyID | CgroupID](m *ebpf.Map) (map[K]map[V]struct{}, error) {
	readInner := func(id uint32) (map[V]struct{}, error) {
		inMap, err := ebpf.NewMapFromID(ebpf.MapID(id))
		if err != nil {
			return nil, fmt.Errorf("error opening inner map: %w", err)
		}
		defer inMap.Close()

		inIter := inMap.Iterate()
		var key V
		var val uint8

		ret := map[V]struct{}{}
		for inIter.Next(&key, &val) {
			ret[key] = struct{}{}
		}

		if err := inIter.Err(); err != nil {
			return nil, fmt.Errorf("error iterating inner map: %w", err)
		}

		return ret, nil

	}

	ret := make(map[K]map[V]struct{})
	var key K
	var id uint32

	iter := m.Iterate()
	for iter.Next(&key, &id) {
		policyids, err := readInner(id)
		if err != nil {
			return nil, err
		}
		ret[key] = policyids
	}

	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("error iterating outer map: %w", err)
	}

	return ret, nil
}

func (m PfMap) readAll() (PfMapDump, error) {
	d, err := readAll[PolicyID, CgroupID](m.policyMap)
	if err != nil {
		return PfMapDump{}, fmt.Errorf("error reading direct map: %w", err)
	}

	var r map[CgroupID]map[PolicyID]struct{}
	if m.cgroupMap != nil {
		r, err = readAll[CgroupID, PolicyID](m.cgroupMap)
		if err != nil {
			return PfMapDump{}, fmt.Errorf("error reading cgroup map: %w", err)
		}
	}

	return PfMapDump{Policy: d, Cgroup: r}, nil
}

// polMap is a simple wrapper for ebpf.Map so that we can write methods for it
type polMap struct {
	Inner     *ebpf.Map
	cgroupMap *ebpf.Map
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
		if err := m.Inner.Update(&cgID, zero, ebpf.UpdateAny); err != nil {
			return &batchError{
				SuccCount: i,
				err:       fmt.Errorf("failed to update policy map (cgroup id: %d): %w", cgID, err),
			}
		}
	}

	return nil
}

// delCgroupIDs delete cgroups ids from the policy map
// todo: use batch operations when supported
func (m polMap) delCgroupIDs(polID PolicyID, cgIDs []CgroupID) error {
	// cgroup map does not exist, so nothing to do here
	if m.cgroupMap == nil {
		return nil
	}

	rmRevCgIDs := []CgroupID{}
	for i, cgID := range cgIDs {
		if err := m.Inner.Delete(&cgID); err != nil {
			return &batchError{
				SuccCount: i,
				err:       fmt.Errorf("failed to delete items from policy map (cgroup id: %d): %w", cgID, err),
			}
		}
		rmRevCgIDs = append(rmRevCgIDs, cgID)
	}

	// update cgroup map
	for _, cgID := range rmRevCgIDs {
		var id uint32
		if err := m.cgroupMap.Lookup(cgID, &id); err != nil { // inner map does not exists
			continue
		}

		inMap, err := ebpf.NewMapFromID(ebpf.MapID(id))
		if err != nil {
			return fmt.Errorf("error opening inner map: %w", err)
		}
		defer inMap.Close()

		var zero uint8
		if err := inMap.Lookup(polID, &zero); err != nil {
			continue
		}

		// policy exists for that cgrpid so delete that
		inMap.Delete(polID)

		// get the inner map size
		sz, err := getMapSize(inMap)
		if err != nil {
			return fmt.Errorf("error getting inner map size: %w", err)
		}

		// we can now delete that outter entry
		if sz == 0 {
			m.cgroupMap.Delete(cgID)
		}
	}

	return nil
}

func OpenMap(fname string) (PfMap, error) {
	base := filepath.Base(fname)
	if base != MapName {
		return PfMap{}, fmt.Errorf("unexpected policy filter map name: %s", base)
	}

	d, err := ebpf.LoadPinnedMap(fname, &ebpf.LoadPinOptions{
		ReadOnly: true,
	})

	if err != nil {
		return PfMap{}, err
	}

	dir := filepath.Dir(fname)
	cgroupMapPath := filepath.Join(dir, CgroupMapName)

	// check if the cgroup map exists
	// the cgroup map may not exist in the case where
	// enable-policy-filter-cgroup-map is false
	var r *ebpf.Map
	if _, err := os.Stat(cgroupMapPath); err == nil {
		r, err = ebpf.LoadPinnedMap(cgroupMapPath, &ebpf.LoadPinOptions{
			ReadOnly: true,
		})
		if err != nil {
			d.Close()
			return PfMap{}, err
		}
	}

	return PfMap{policyMap: d, cgroupMap: r}, err
}

func (m PfMap) Close() {
	m.policyMap.Close()
	if m.cgroupMap != nil {
		m.cgroupMap.Close()
	}
}

func (m PfMap) Dump() (PfMapDump, error) {
	return m.readAll()
}

func (m PfMap) AddCgroup(polID PolicyID, cgID CgroupID) error {
	// direct map update
	var innerID uint32

	if err := m.policyMap.Lookup(&polID, &innerID); err != nil {
		return fmt.Errorf("failed to lookup policy id %d: %w", polID, err)
	}

	inMap, err := ebpf.NewMapFromID(ebpf.MapID(innerID))
	if err != nil {
		return fmt.Errorf("error opening inner map: %w", err)
	}
	defer inMap.Close()

	val := uint8(0)
	if err := inMap.Update(&cgID, &val, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("error updating inner map: %w", err)
	}

	// cgroup map update
	if err := addPolicyIDMapping(m.cgroupMap, polID, cgID); err != nil {
		return fmt.Errorf("error updating cgroup map: %w", err)
	}

	return nil
}
