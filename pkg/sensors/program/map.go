// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// We allow to define several types of maps:
//
//    MapTypeGlobal MapType = iota
//    MapTypePolicy
//    MapTypeSensor
//    MapTypeProgram
//
//  Each type defines the maps position in the sysfs hierarchy:
//
//    MapTypeGlobal:     /sys/fs/bpf/tetragon/map
//    MapTypePolicy:     /sys/fs/bpf/tetragon/policy/map
//    MapTypeSensor:     /sys/fs/bpf/tetragon/policy/sensor/map
//    MapTypeProgram:    /sys/fs/bpf/tetragon/policy/sensor/program/map
//
//  Each type has appropriate helper defined, which sets map's
//  path to specific level of sysfs hierarchy:
//
//    MapTypeGlobal:     MapBuilder
//    MapTypePolicy:     MapBuilderPolicy
//    MapTypeSensor:     MapBuilderSensor
//    MapTypeProgram:    MapBuilderProgram
//
//  It's possible to share map between more programs like:
//
//     m := MapBuilderSensor("map", prog1, prog2, prog3)
//
//  All prog1-3 programs will attach to m1 through:
//
//    /sys/fs/bpf/tetragon/policy/sensor/map
//
//  The idea is to share map on higher level which denotes to scope
//  of the map, like:
//
//     /sys/fs/bpf/tetragon/map
//      - map is global shared with all policies/sensors/programs
//
//     /sys/fs/bpf/tetragon/policy/map
//      - map is local for policy, shared by all its sensors/programs
//
//     /sys/fs/bpf/tetragon/policy/sensors/map
//      - map is local for sensor, shared by all its programs
//
//     /sys/fs/bpf/tetragon/policy/sensors/program/map
//      - map is local for program, not shared at all
//
//  NOTE Please do not share MapTypeProgram maps, it brings confusion.
//
//  Each map declares the ownership of the map. The map can be either
//  owner of the map (via MapBuilder* helpers) or as an user (MapUser*
//  helpers.
//
//  Map owner object owns the pinned map and when loading it sets (and
//  potentially overwrite) the map's spec and its max entries value.
//
//  Map user object object is just using the pinned map and follows its
//  setup and will fail if the pinned map differs in spec or configured
//  max entries value.

package program

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/sirupsen/logrus"
)

type MaxEntries struct {
	Val uint32
	Set bool
}

type MapType int

const (
	MapTypeGlobal MapType = iota
	MapTypePolicy
	MapTypeSensor
	MapTypeProgram
)

type MapOpts struct {
	Type  MapType
	Owner bool
}

// Map represents BPF maps.
type Map struct {
	Name         string
	PinPath      string
	Prog         *Program
	PinState     State
	MapHandle    *ebpf.Map
	Entries      MaxEntries
	InnerEntries MaxEntries
	Type         MapType
	Owner        bool
}

func (m *Map) String() string {
	return fmt.Sprintf("Map{Name:%s PinPath:%s Owner:%t}", m.Name, m.PinPath, m.IsOwner())
}

// globalMaps keeps a record of all global maps to exclude them from per policy
// memory map accounting.
var globalMaps = struct {
	maps map[string]bool
	mu   sync.RWMutex
}{
	make(map[string]bool),
	sync.RWMutex{},
}

func IsGlobalMap(name string) bool {
	if len(name) > 15 {
		name = name[:15]
	}
	globalMaps.mu.RLock()
	defer globalMaps.mu.RUnlock()
	return globalMaps.maps[name]
}

func AddGlobalMap(name string) {
	if len(name) > 15 {
		name = name[:15]
	}
	globalMaps.mu.Lock()
	defer globalMaps.mu.Unlock()
	globalMaps.maps[name] = true
}

func DeleteGlobMap(name string) {
	if len(name) > 15 {
		name = name[:15]
	}
	globalMaps.mu.Lock()
	defer globalMaps.mu.Unlock()
	delete(globalMaps.maps, name)
}

// Map holds pointer to Program object as a source of its ebpf object
// file. We assume all the programs sharing the map have same map
// definition, so it's ok to use the first program if there's more.
//
//	m.prog -> lds[0]
//
// Every program has PinMap map that links map name woth the map object,
// so the loader has all program's map object available.
//
//	p.PinMap["map1"] = &map1
//	p.PinMap["map2"] = &map2
//	...
//	p.PinMap["mapX"] = &mapX
func mapBuilder(name string, ty MapType, owner bool, lds ...*Program) *Map {
	var prog *Program
	if len(lds) != 0 {
		prog = lds[0]
	}
	m := &Map{name, "", prog, Idle(), nil, MaxEntries{0, false}, MaxEntries{0, false}, ty, owner}
	for _, ld := range lds {
		ld.PinMap[name] = m
	}
	return m
}

func MapBuilder(name string, lds ...*Program) *Map {
	return mapBuilder(name, MapTypeGlobal, true, lds...)
}

func MapBuilderProgram(name string, lds ...*Program) *Map {
	return mapBuilder(name, MapTypeProgram, true, lds...)
}

func MapBuilderSensor(name string, lds ...*Program) *Map {
	return mapBuilder(name, MapTypeSensor, true, lds...)
}

func MapBuilderPolicy(name string, lds ...*Program) *Map {
	return mapBuilder(name, MapTypePolicy, true, lds...)
}

func MapBuilderType(name string, ty MapType, lds ...*Program) *Map {
	return mapBuilder(name, ty, true, lds...)
}

func MapBuilderOpts(name string, opts MapOpts, lds ...*Program) *Map {
	return mapBuilder(name, opts.Type, opts.Owner, lds...)
}

func mapUser(name string, ty MapType, prog *Program) *Map {
	return &Map{name, "", prog, Idle(), nil, MaxEntries{0, false}, MaxEntries{0, false}, ty, false}
}

func MapUser(name string, prog *Program) *Map {
	return mapUser(name, MapTypeGlobal, prog)
}

func MapUserProgram(name string, prog *Program) *Map {
	return mapUser(name, MapTypeProgram, prog)
}

func MapUserSensor(name string, prog *Program) *Map {
	return mapUser(name, MapTypeSensor, prog)
}

func MapUserPolicy(name string, prog *Program) *Map {
	return mapUser(name, MapTypePolicy, prog)
}

func MapUserFrom(m *Map) *Map {
	return mapUser(m.Name, m.Type, m.Prog)
}

func PolicyMapPath(mapDir, policy, name string) string {
	return filepath.Join(mapDir, policy, name)
}

func (m *Map) IsOwner() bool {
	return m.Owner
}

func (m *Map) Unload(unpin bool) error {
	log := logger.GetLogger().WithField("map", m.Name).WithField("pin", m.PinPath)
	if !m.PinState.IsLoaded() {
		log.WithField("count", m.PinState.count).Debug("Refusing to unload map as it is not loaded")
		return nil
	}
	if count := m.PinState.RefDec(); count > 0 {
		log.WithField("count", count).Debug("Reference exists, not unloading map yet")
		return nil
	}
	log.Debug("map was unloaded")
	if m.MapHandle != nil {
		if m.IsOwner() && unpin {
			m.MapHandle.Unpin()
			if m.Type == MapTypeGlobal {
				DeleteGlobMap(m.Name)
			}
		}
		err := m.MapHandle.Close()
		m.MapHandle = nil
		return err
	}
	return nil
}

func (m *Map) New(spec *ebpf.MapSpec) error {
	var err error
	m.MapHandle, err = ebpf.NewMap(spec)
	return err
}

func (m *Map) Pin(path string) error {
	return m.MapHandle.Pin(path)
}

func (m *Map) LoadPinnedMap(path string) error {
	var err error
	m.MapHandle, err = ebpf.LoadPinnedMap(path, nil)
	return err
}

// MapSpec.Compatible will be exported in ebpf v0.9.3,
// meanwhile steal that and make it our own ;-)
func compatible(ms *ebpf.MapSpec, m *ebpf.Map) error {
	switch {
	case m.Type() != ms.Type:
		return fmt.Errorf("expected type %v, got %v: %w", ms.Type, m.Type(), ebpf.ErrMapIncompatible)

	case m.KeySize() != ms.KeySize:
		return fmt.Errorf("expected key size %v, got %v: %w", ms.KeySize, m.KeySize(), ebpf.ErrMapIncompatible)

	case m.ValueSize() != ms.ValueSize:
		return fmt.Errorf("expected value size %v, got %v: %w", ms.ValueSize, m.ValueSize(), ebpf.ErrMapIncompatible)

	case !(ms.Type == ebpf.PerfEventArray && ms.MaxEntries == 0) &&
		m.MaxEntries() != ms.MaxEntries:
		return fmt.Errorf("expected max entries %v, got %v: %w", ms.MaxEntries, m.MaxEntries(), ebpf.ErrMapIncompatible)

	case m.Flags() != ms.Flags:
		return fmt.Errorf("expected flags %v, got %v: %w", ms.Flags, m.Flags(), ebpf.ErrMapIncompatible)
	}
	return nil
}

func (m *Map) IsCompatibleWith(spec *ebpf.MapSpec) error {
	return compatible(spec, m.MapHandle)
}

func (m *Map) Close() error {
	return m.MapHandle.Close()
}

func (m *Map) GetFD() (int, error) {
	if m.MapHandle == nil {
		return 0, fmt.Errorf("map %s is not loaded", m.Name)
	}
	return m.MapHandle.FD(), nil
}

func (m *Map) LoadOrCreatePinnedMap(pinPath string, mapSpec *ebpf.MapSpec) error {
	if m.MapHandle != nil {
		logger.GetLogger().WithFields(logrus.Fields{
			"map-name": m.Name,
		}).Warn("LoadOrCreatePinnedMap called with non-nil map, will close and continue.")
		m.MapHandle.Close()
	}

	mh, err := LoadOrCreatePinnedMap(pinPath, mapSpec, m.IsOwner())
	if err != nil {
		return err
	}

	m.MapHandle = mh
	m.PinState.RefInc()
	if m.Type == MapTypeGlobal {
		AddGlobalMap(m.Name)
	}
	return nil
}

func isValidSubdir(d string) bool {
	dir := filepath.Base(d)
	return dir != "." && dir != ".."
}

func LoadOrCreatePinnedMap(pinPath string, mapSpec *ebpf.MapSpec, create bool) (*ebpf.Map, error) {
	var err error
	// Try to open the pinPath and if it exist use the previously
	// pinned map otherwise pin the map and next user will find
	// it here.
	if _, err = os.Stat(pinPath); err == nil {
		m, err := ebpf.LoadPinnedMap(pinPath, nil)
		if err != nil {
			return nil, fmt.Errorf("loading pinned map from path '%s' failed: %w", pinPath, err)
		}
		if err := compatible(mapSpec, m); err != nil {
			logger.GetLogger().WithError(err).WithFields(logrus.Fields{
				"path":     pinPath,
				"map-name": mapSpec.Name,
			}).Warn("incompatible map found")
			m.Close()
			// If we are creating the map, let's ignore the compatibility error,
			// remove the pin and create the map with our spec.
			if create {
				logger.GetLogger().WithField("map", mapSpec.Name).
					Warn("will delete and recreate")
				os.Remove(pinPath)
				return createPinnedMap(pinPath, mapSpec)
			}
			return nil, fmt.Errorf("incompatible map '%s'", pinPath)
		}
		return m, nil
	}
	if create {
		return createPinnedMap(pinPath, mapSpec)
	}
	return nil, err
}

func createPinnedMap(pinPath string, mapSpec *ebpf.MapSpec) (*ebpf.Map, error) {
	// check if PinName has directory portion and create it,
	// filepath.Dir returns '.' for filename without dir portion
	if dir := filepath.Dir(pinPath); isValidSubdir(dir) {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create subbir for '%s': %w", mapSpec.Name, err)
		}
	}

	// either there's no pin file or the map spec does not match
	m, err := ebpf.NewMap(mapSpec)
	if err != nil {
		return nil, fmt.Errorf("failed to create map '%s': %w", mapSpec.Name, err)
	}

	if err := m.Pin(pinPath); err != nil {
		m.Close()
		return nil, fmt.Errorf("failed to pin to %s: %w", pinPath, err)
	}

	return m, nil
}

func GetMaxEntriesPinnedMap(pinPath string) (uint32, error) {
	m, err := ebpf.LoadPinnedMap(pinPath, nil)
	if err != nil {
		return 0, fmt.Errorf("loading pinned map from path '%s' failed: %w", pinPath, err)
	}
	defer m.Close()
	return m.MaxEntries(), nil
}

func (m *Map) SetMaxEntries(maximum int) {
	m.Entries = MaxEntries{uint32(maximum), true}
}

func (m *Map) SetInnerMaxEntries(maximum int) {
	m.InnerEntries = MaxEntries{uint32(maximum), true}
}

func (m *Map) GetMaxEntries() (uint32, bool) {
	return m.Entries.Val, m.Entries.Set
}

func (m *Map) GetMaxInnerEntries() (uint32, bool) {
	return m.InnerEntries.Val, m.InnerEntries.Set
}
