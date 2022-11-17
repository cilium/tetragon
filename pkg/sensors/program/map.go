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
	MapHandle *ebpf.Map
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
		m.MapHandle.Unpin()
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
