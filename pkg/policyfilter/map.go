// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package policyfilter

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"github.com/cilium/ebpf"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

const (
	MapName       = "policy_filter_maps"
	CgroupMapName = "policy_filter_cgroup_maps"
)

// map operations used by policyfilter.

// PfMap wraps policy filter maps using program.Map for consistent map lifecycle
// management and integration with Tetragon's sensor loading infrastructure.
type PfMap struct {
	policyMap *program.Map // policy_filter_maps
	cgroupMap *program.Map // policy_filter_cgroup_maps
}

// openMap creates a program.Map from the given spec and pins it to bpffs.
// It uses program.LoadOrCreatePinnedMap for consistent map lifecycle management.
func openMap(spec *ebpf.CollectionSpec, mapName string, innerMaxEntries uint32) (*program.Map, error) {
	mapSpec, ok := spec.Maps[mapName]
	if !ok {
		return nil, fmt.Errorf("%s not found in object file", mapName)
	}

	// bpf-side sets max_entries to 1. Later kernels (5.10) can deal with
	// inserting a different size of inner-map, but for older kernels, we
	// fix the spec here.
	mapSpec.InnerMap.MaxEntries = innerMaxEntries

	mapDir := bpf.MapPrefixPath()
	pinPath := filepath.Join(mapDir, mapName)

	// Remove any existing pinned map to ensure we create a fresh one
	os.Remove(pinPath)
	os.MkdirAll(mapDir, 0755)

	// Create the program.Map wrapper
	m := &program.Map{
		Name:     mapName,
		PinPath:  pinPath,
		Type:     program.MapTypeGlobal,
		Owner:    true,
		PinState: program.Idle(),
	}

	// Set inner max entries for hash-of-hashes maps
	m.SetInnerMaxEntries(int(innerMaxEntries))

	// Use LoadOrCreatePinnedMap for consistent map handling
	if err := m.LoadOrCreatePinnedMap(pinPath, mapSpec); err != nil {
		return nil, fmt.Errorf("failed to load or create pinned map %s: %w", mapName, err)
	}

	// Register as global map for memory accounting exclusion
	program.AddGlobalMap(mapName)

	return m, nil
}

// newPfMap returns a new policy filter map using program.Map abstraction.
func newPfMap(enableCgroupMap bool) (PfMap, error) {
	// use the generic kprobe program, to find the policy filter map spec
	objName, _ := config.GenericKprobeObjs(false)
	objPath, err := config.FindProgramFile(objName)
	if err != nil {
		return PfMap{}, fmt.Errorf("loading spec for %s failed: %w", objPath, err)
	}
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
			ret.policyMap.Unload(true)
			return PfMap{}, fmt.Errorf("opening cgroup map %s failed: %w", CgroupMapName, err)
		}
	}

	return ret, nil
}

// releaseProgramMap releases a program.Map by unloading and unpinning it.
func releaseProgramMap(m *program.Map) error {
	// this may happen in the case where the cgroup map is not enabled
	if m == nil {
		return nil
	}

	// Unload with unpin=true to remove the bpffs file
	if err := m.Unload(true); err != nil {
		return err
	}

	// Remove from global maps registry
	program.DeleteGlobMap(m.Name)

	return nil
}

// release closes the policy filter bpf maps and removes (unpins) the bpffs files
func (m PfMap) release() error {
	return errors.Join(
		releaseProgramMap(m.policyMap),
		releaseProgramMap(m.cgroupMap),
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

// policyMapHandle returns the underlying ebpf.Map handle for the policy map.
func (m PfMap) policyMapHandle() *ebpf.Map {
	if m.policyMap == nil {
		return nil
	}
	return m.policyMap.MapHandle
}

// cgroupMapHandle returns the underlying ebpf.Map handle for the cgroup map, or nil if not enabled.
func (m PfMap) cgroupMapHandle() *ebpf.Map {
	if m.cgroupMap == nil {
		return nil
	}
	return m.cgroupMap.MapHandle
}

// newPolicyMap adds and initializes a new policy map
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
		cgroupMap: m.cgroupMapHandle(),
	}
	if err := ret.addCgroupIDs(cgIDs); err != nil {
		ret.Inner.Close()
		return polMap{}, fmt.Errorf("failed to update policy (id=%d): %w", polID, err)
	}

	// update outer map
	// NB(kkourt): use UpdateNoExist because we expect only a single policy with a given id
	if err := m.policyMap.MapHandle.Update(polID, uint32(ret.Inner.FD()), ebpf.UpdateNoExist); err != nil {
		ret.Inner.Close()
		return polMap{}, fmt.Errorf("failed to insert inner policy (id=%d) map: %w", polID, err)
	}

	// update cgroup map
	for _, cgID := range cgIDs {
		if err := addPolicyIDMapping(m.cgroupMapHandle(), polID, cgID); err != nil {
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
	cgMap := m.cgroupMapHandle()
	if cgMap == nil {
		return nil
	}

	var key CgroupID
	var id uint32

	cgIDs := []CgroupID{}
	iter := cgMap.Iterate()
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
		if err := cgMap.Delete(cgID); err != nil {
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
	d, err := readAll[PolicyID, CgroupID](m.policyMap.MapHandle)
	if err != nil {
		return PfMapDump{}, fmt.Errorf("error reading direct map: %w", err)
	}

	var r map[CgroupID]map[PolicyID]struct{}
	if m.cgroupMap != nil {
		r, err = readAll[CgroupID, PolicyID](m.cgroupMap.MapHandle)
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

// OpenMap opens an existing pinned policy filter map for read-only access.
// This is used by CLI tools like `tetra policyfilter dump`.
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

	// Wrap in program.Map for consistent interface
	policyProgMap := &program.Map{
		Name:      MapName,
		PinPath:   fname,
		MapHandle: d,
		Type:      program.MapTypeGlobal,
		Owner:     false, // Read-only, not owner
		PinState:  program.Idle(),
	}

	dir := filepath.Dir(fname)
	cgroupMapPath := filepath.Join(dir, CgroupMapName)

	// check if the cgroup map exists
	// the cgroup map may not exist in the case where
	// enable-policy-filter-cgroup-map is false
	var cgroupProgMap *program.Map
	if _, err := os.Stat(cgroupMapPath); err == nil {
		r, err := ebpf.LoadPinnedMap(cgroupMapPath, &ebpf.LoadPinOptions{
			ReadOnly: true,
		})
		if err != nil {
			d.Close()
			return PfMap{}, err
		}
		cgroupProgMap = &program.Map{
			Name:      CgroupMapName,
			PinPath:   cgroupMapPath,
			MapHandle: r,
			Type:      program.MapTypeGlobal,
			Owner:     false, // Read-only, not owner
			PinState:  program.Idle(),
		}
	}

	return PfMap{policyMap: policyProgMap, cgroupMap: cgroupProgMap}, nil
}

// Close closes the policy filter maps.
func (m PfMap) Close() {
	if m.policyMap != nil {
		m.policyMap.Close()
	}
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

	if err := m.policyMap.MapHandle.Lookup(&polID, &innerID); err != nil {
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
	if err := addPolicyIDMapping(m.cgroupMapHandle(), polID, cgID); err != nil {
		return fmt.Errorf("error updating cgroup map: %w", err)
	}

	return nil
}
