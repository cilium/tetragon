package program

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/logger"
)

// Map represents BPF maps.
type Map struct {
	Name      string
	PinName   string
	Prog      *Program
	PinState  State
	mapHandle *ebpf.Map
}

func MapBuilder(name string, ld *Program) *Map {
	return &Map{name, name, ld, Idle(), nil}
}

func MapBuilderPin(name, pin string, ld *Program) *Map {
	ld.PinMap[name] = pin
	return &Map{name, pin, ld, Idle(), nil}
}

func (m *Map) Unload() error {
	log := logger.GetLogger().WithField("map", m.Name).WithField("pin", m.PinName)
	if !m.PinState.IsLoaded() || m.PinState.IsDisabled() {
		log.WithField("count", m.PinState.count).Debug("Refusing to unload map as it is not loaded or is disabled")
		return nil
	}
	if count := m.PinState.RefDec(); count > 0 {
		log.WithField("count", count).Debug("Reference exists, not unloading map yet")
		return nil
	}
	log.Info("map was unloaded")
	if m.mapHandle != nil {
		m.mapHandle.Unpin()
		err := m.mapHandle.Close()
		m.mapHandle = nil
		return err
	}
	return nil
}

func (m *Map) New(spec *ebpf.MapSpec) error {
	var err error
	m.mapHandle, err = ebpf.NewMap(spec)
	return err
}

func (m *Map) Pin(path string) error {
	return m.mapHandle.Pin(path)
}

func (m *Map) LoadPinnedMap(path string) error {
	var err error
	m.mapHandle, err = ebpf.LoadPinnedMap(path, nil)
	return err
}

func (m *Map) Close() error {
	return m.mapHandle.Close()
}

func (m *Map) GetFD() (int, error) {
	if m.mapHandle == nil {
		return 0, fmt.Errorf("map %s is not loaded", m.Name)
	}
	return m.mapHandle.FD(), nil
}
