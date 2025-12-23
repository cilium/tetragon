// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package sensors

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"

	cachedbtf "github.com/cilium/tetragon/pkg/btf"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

func (s *Sensor) setMapPinPath(m *program.Map) {
	policy := s.policyDir()
	switch m.Type {
	case program.MapTypeGlobal:
		m.PinPath = filepath.Join(m.Name)
	case program.MapTypePolicy:
		m.PinPath = filepath.Join(policy, m.Name)
	case program.MapTypeSensor:
		m.PinPath = filepath.Join(policy, s.Name, m.Name)
	case program.MapTypeProgram:
		m.PinPath = filepath.Join(policy, s.Name, m.Prog.PinName, m.Name)
	}
}

func (s *Sensor) preLoadMaps(bpfDir string, loadedMaps []*program.Map) ([]*program.Map, error) {
	loaderCache := newLoaderCache()
	for _, m := range s.Maps {
		if err := s.loadMap(bpfDir, loaderCache, m); err != nil {
			return loadedMaps, fmt.Errorf("tetragon, aborting could not load sensor BPF maps: %w", err)
		}
		loadedMaps = append(loadedMaps, m)
	}
	return loadedMaps, nil
}

// loadMap loads BPF map in the sensor.
func (s *Sensor) loadMap(bpfDir string, loaderCache *loaderCache, m *program.Map) error {
	l := logger.GetLogger()
	if m.PinState.IsLoaded() {
		l.Info("map is already loaded, incrementing reference count", "sensor", s.Name, "map", m.Name)
		m.PinState.RefInc()
		return nil
	}

	spec, err := loaderCache.loadCollectionSpec(m.Prog.Name)
	if err != nil {
		return fmt.Errorf("failed to open collection '%s': %w", m.Prog.Name, err)
	}
	mapSpec, ok := spec.Maps[m.Name]
	if !ok {
		return fmt.Errorf("map '%s' not found from '%s'", m.Name, m.Prog.Name)
	}

	// code below will modify mapSpec. Crate a copy so that the original spec (which is reused
	// via the loaderCache for different inscanes of the map) is not modified.
	mapSpec = mapSpec.Copy()

	s.setMapPinPath(m)
	pinPath := filepath.Join(bpfDir, m.PinPath)

	if m.IsOwner() {
		// If map is the owner we set configured maximum entries
		// directly to map spec.
		if maximum, ok := m.GetMaxEntries(); ok {
			mapSpec.MaxEntries = maximum
		}

		if innerMax, ok := m.GetMaxInnerEntries(); ok {
			if innerMs := mapSpec.InnerMap; innerMs != nil {
				mapSpec.InnerMap.MaxEntries = innerMax
			}
		}

		// Apply or clear BPF_F_NO_PREALLOC flag based on map configuration.
		mapSpec.Flags = m.GetPreallocFlags(mapSpec.Flags)
	} else {
		// If map is NOT the owner we follow the maximum entries
		// of the pinned map and update the spec with that.
		maximum, err := program.GetMaxEntriesPinnedMap(pinPath)
		if err != nil {
			return err
		}
		mapSpec.MaxEntries = maximum

		// 'm' is not the owner but for some reason requires maximum
		// entries setup, make sure it matches the pinned map.
		if maximum, ok := m.GetMaxEntries(); ok {
			if mapSpec.MaxEntries != maximum {
				return fmt.Errorf("failed to load map '%s' max entries mismatch: %d %d",
					m.Name, mapSpec.MaxEntries, maximum)
			}
		}

		m.SetMaxEntries(int(maximum))
	}

	// Disable content loading at this point, we just care about the map,
	// the content will be loaded when the whole object gets loaded.
	mapSpec.Contents = nil

	if err := m.LoadOrCreatePinnedMap(pinPath, mapSpec); err != nil {
		return fmt.Errorf("failed to load map '%s' for sensor '%s': %w", m.Name, s.Name, err)
	}

	l.Debug("tetragon, map loaded.", "sensor", s.Name, "map", m.Name, "path", pinPath, "max", m.Entries, "noprealloc", m.NoPrealloc)

	return nil
}

func observerLoadInstance(bpfDir string, load *program.Program, maps []*program.Map) error {
	version, _, err := kernels.GetKernelVersion(option.Config.KernelVersion, option.Config.ProcFS)
	if err != nil {
		return err
	}

	l := logger.GetLogger()
	l.Debug(fmt.Sprintf("observerLoadInstance %s %d", load.Name, version), "prog", load.Name, "kern_version", version)
	switch load.Type {
	case "tracepoint":
		err = loadInstance(bpfDir, load, maps, version, option.Config.Verbosity)
		if err != nil {
			l.Info("Failed to load, trying to remove and retrying", "tracepoint", load.Name)
			load.Unload(true)
			err = loadInstance(bpfDir, load, maps, version, option.Config.Verbosity)
		}
		if err != nil {
			return fmt.Errorf("failed prog %s kern_version %d LoadTracingProgram: %w",
				load.Name, version, err)
		}
	case "raw_tracepoint", "raw_tp":
		err = loadInstance(bpfDir, load, maps, version, option.Config.Verbosity)
		if err != nil {
			l.Info("Failed to load, trying to remove and retrying", "raw_tracepoint", load.Name)
			load.Unload(true)
			err = loadInstance(bpfDir, load, maps, version, option.Config.Verbosity)
		}
		if err != nil {
			return fmt.Errorf("failed prog %s kern_version %d LoadRawTracepointProgram: %w",
				load.Name, version, err)
		}
	default:
		err = loadInstance(bpfDir, load, maps, version, option.Config.Verbosity)
		if err != nil && load.ErrorFatal {
			return fmt.Errorf("failed prog %s kern_version %d loadInstance: %w",
				load.Name, version, err)
		}
	}
	return nil
}

func loadInstance(bpfDir string, load *program.Program, maps []*program.Map, version, verbose int) error {
	// Check if the load.type is a standard program type. If so, use the standard loader.
	loadFn, ok := standardTypes[load.Type]
	if ok {
		logger.GetLogger().Debug("Loading BPF program", "Program", load.Name, "Type", load.Type, "Attach", load.Attach)
		return loadFn(bpfDir, load, maps, verbose)
	}
	// Otherwise, check for a registered probe type. If one exists, use that.
	probe, ok := registeredProbeLoad[load.Type]
	if ok {
		logger.GetLogger().Debug("Loading registered BPF probe", "Program", load.Name, "Type", load.Type, "Attach", load.Attach)
		// Registered probes need extra setup
		version = kernels.FixKernelVersion(version)
		return probe.LoadProbe(LoadProbeArgs{
			BPFDir:  bpfDir,
			Load:    load,
			Version: version,
			Verbose: verbose,
			Maps:    maps,
		})
	}

	return fmt.Errorf("program %s has unregistered type '%s'", load.Label, load.Type)
}

func observerMinReqs() (bool, error) {
	_, _, err := kernels.GetKernelVersion(option.Config.KernelVersion, option.Config.ProcFS)
	if err != nil {
		return false, errors.New("kernel version lookup failed, required for kprobe")
	}
	return true, nil
}

func flushKernelSpec() {
	btf.FlushKernelSpec()
}

func getCachedBTFFile() string {
	return cachedbtf.GetCachedBTFFile()
}

type loaderCache struct {
	specCache map[string]*ebpf.CollectionSpec
}

func newLoaderCache() *loaderCache {
	return &loaderCache{
		specCache: make(map[string]*ebpf.CollectionSpec),
	}
}

func (c *loaderCache) loadCollectionSpec(n string) (*ebpf.CollectionSpec, error) {
	ret, ok := c.specCache[n]
	if ok {
		return ret, nil
	}

	ret, err := ebpf.LoadCollectionSpec(n)
	if err == nil {
		c.specCache[n] = ret
	}
	return ret, err
}
