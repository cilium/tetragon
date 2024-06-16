// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package program

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
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
func mapBuilder(name string, ty MapType, lds ...*Program) *Map {
	m := &Map{name, "", lds[0], Idle(), nil, MaxEntries{0, false}, MaxEntries{0, false}, ty}
	for _, ld := range lds {
		ld.PinMap[name] = m
	}
	return m
}

func MapBuilder(name string, lds ...*Program) *Map {
	return mapBuilder(name, MapTypeGlobal, lds...)
}

func MapBuilderProgram(name string, lds ...*Program) *Map {
	return mapBuilder(name, MapTypeProgram, lds...)
}

func MapBuilderSensor(name string, lds ...*Program) *Map {
	return mapBuilder(name, MapTypeSensor, lds...)
}

func MapBuilderPolicy(name string, lds ...*Program) *Map {
	return mapBuilder(name, MapTypePolicy, lds...)
}

func MapBuilderType(name string, ty MapType, lds ...*Program) *Map {
	return mapBuilder(name, ty, lds...)
}

func PolicyMapPath(mapDir, policy, name string) string {
	return filepath.Join(mapDir, policy, name)
}

func (m *Map) Unload() error {
	log := logger.GetLogger().WithField("map", m.Name).WithField("pin", m.Name)
	if !m.PinState.IsLoaded() {
		log.WithField("count", m.PinState.count).Debug("Refusing to unload map as it is not loaded")
		return nil
	}
	if count := m.PinState.RefDec(); count > 0 {
		log.WithField("count", count).Debug("Reference exists, not unloading map yet")
		return nil
	}
	log.Info("map was unloaded")
	if m.MapHandle != nil {
		if !option.Config.KeepSensorsOnExit {
			m.MapHandle.Unpin()
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

	mh, err := LoadOrCreatePinnedMap(pinPath, mapSpec)
	if err != nil {
		return err
	}

	m.MapHandle = mh
	m.PinState.RefInc()
	return nil
}

func isValidSubdir(d string) bool {
	dir := filepath.Base(d)
	return dir != "." && dir != ".."
}

func LoadOrCreatePinnedMap(pinPath string, mapSpec *ebpf.MapSpec) (*ebpf.Map, error) {
	// Try to open the pinPath and if it exist use the previously
	// pinned map otherwise pin the map and next user will find
	// it here.
	if _, err := os.Stat(pinPath); err == nil {
		m, err := ebpf.LoadPinnedMap(pinPath, nil)
		if err != nil {
			return nil, fmt.Errorf("loading pinned map from path '%s' failed: %w", pinPath, err)
		}
		if err := compatible(mapSpec, m); err != nil {
			logger.GetLogger().WithError(err).WithFields(logrus.Fields{
				"path":     pinPath,
				"map-name": mapSpec.Name,
			}).Warn("tetragon, incompatible map found: will delete and recreate")
			m.Close()
			os.Remove(pinPath)
		} else {
			return m, nil
		}
	}

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

func (m *Map) SetMaxEntries(max int) {
	m.Entries = MaxEntries{uint32(max), true}
}

func (m *Map) SetInnerMaxEntries(max int) {
	m.InnerEntries = MaxEntries{uint32(max), true}
}

func (m *Map) GetMaxEntries() (uint32, bool) {
	return m.Entries.Val, m.Entries.Set
}

func (m *Map) GetMaxInnerEntries() (uint32, bool) {
	return m.InnerEntries.Val, m.InnerEntries.Set
}
