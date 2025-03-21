// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package sensors

import (
	"fmt"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	cachedbtf "github.com/cilium/tetragon/pkg/btf"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/sirupsen/logrus"
)

// Load loads the sensor, by loading all the BPF programs and maps.
func (s *Sensor) Load(bpfDir string) (err error) {
	if s == nil {
		return nil
	}

	if s.Destroyed {
		return fmt.Errorf("sensor %s has been previously destroyed, please recreate it before loading", s.Name)
	}

	logger.GetLogger().WithField("metadata", cachedbtf.GetCachedBTFFile()).Info("BTF file: using metadata file")
	if _, err = observerMinReqs(); err != nil {
		return fmt.Errorf("tetragon, aborting minimum requirements not met: %w", err)
	}

	var (
		loadedMaps  []*program.Map
		loadedProgs []*program.Program
	)

	s.createDirs(bpfDir)
	defer func() {
		if err != nil {
			for _, m := range loadedMaps {
				m.Unload(true)
			}
			for _, p := range loadedProgs {
				unloadProgram(p, true)
			}
			s.removeDirs()
		}
	}()

	l := logger.GetLogger()

	l.WithField("name", s.Name).Info("Loading sensor")
	if s.Loaded {
		return fmt.Errorf("loading sensor %s failed: sensor already loaded", s.Name)
	}

	_, verStr, _ := kernels.GetKernelVersion(option.Config.KernelVersion, option.Config.ProcFS)
	l.Infof("Loading kernel version %s", verStr)

	if err = s.FindPrograms(); err != nil {
		return fmt.Errorf("tetragon, aborting could not find BPF programs: %w", err)
	}

	for _, m := range s.Maps {
		if err = s.loadMap(bpfDir, m); err != nil {
			return fmt.Errorf("tetragon, aborting could not load sensor BPF maps: %w", err)
		}
		loadedMaps = append(loadedMaps, m)
	}

	for _, p := range s.Progs {
		if p.LoadState.IsLoaded() {
			l.WithField("prog", p.Name).Info("BPF prog is already loaded, incrementing reference count")
			p.LoadState.RefInc()
			continue
		}

		if err = observerLoadInstance(bpfDir, p, s.Maps); err != nil {
			return err
		}
		p.LoadState.RefInc()
		loadedProgs = append(loadedProgs, p)
		l.WithField("prog", p.Name).WithField("label", p.Label).Debugf("BPF prog was loaded")
	}

	// Add the *loaded* programs and maps, so they can be unloaded later
	progsAdd(s.Progs)
	AllMaps = append(AllMaps, s.Maps...)

	if s.PostLoadHook != nil {
		if err := s.PostLoadHook(); err != nil {
			logger.GetLogger().WithError(err).WithField("sensor", s.Name).Warn("Post load hook failed")
		}
	}

	// cleanup the BTF once we have loaded all sensor's program
	btf.FlushKernelSpec()

	l.WithFields(logrus.Fields{
		"sensor": s.Name,
		"maps":   loadedMaps,
		"progs":  loadedProgs,
	}).Infof("Loaded BPF maps and events for sensor successfully")
	s.Loaded = true
	return nil
}

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

// loadMap loads BPF map in the sensor.
func (s *Sensor) loadMap(bpfDir string, m *program.Map) error {
	l := logger.GetLogger()
	if m.PinState.IsLoaded() {
		l.WithFields(logrus.Fields{
			"sensor": s.Name,
			"map":    m.Name,
		}).Info("map is already loaded, incrementing reference count")
		m.PinState.RefInc()
		return nil
	}

	spec, err := ebpf.LoadCollectionSpec(m.Prog.Name)
	if err != nil {
		return fmt.Errorf("failed to open collection '%s': %w", m.Prog.Name, err)
	}
	mapSpec, ok := spec.Maps[m.Name]
	if !ok {
		return fmt.Errorf("map '%s' not found from '%s'", m.Name, m.Prog.Name)
	}

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

	l.WithFields(logrus.Fields{
		"sensor": s.Name,
		"map":    m.Name,
		"path":   pinPath,
		"max":    m.Entries,
	}).Debug("tetragon, map loaded.")

	return nil
}

func observerLoadInstance(bpfDir string, load *program.Program, maps []*program.Map) error {
	version, _, err := kernels.GetKernelVersion(option.Config.KernelVersion, option.Config.ProcFS)
	if err != nil {
		return err
	}

	l := logger.GetLogger()
	l.WithFields(logrus.Fields{
		"prog":         load.Name,
		"kern_version": version,
	}).Debugf("observerLoadInstance %s %d", load.Name, version)
	if load.Type == "tracepoint" {
		err = loadInstance(bpfDir, load, maps, version, option.Config.Verbosity)
		if err != nil {
			l.WithField(
				"tracepoint", load.Name,
			).Info("Failed to load, trying to remove and retrying")
			load.Unload(true)
			err = loadInstance(bpfDir, load, maps, version, option.Config.Verbosity)
		}
		if err != nil {
			return fmt.Errorf("failed prog %s kern_version %d LoadTracingProgram: %w",
				load.Name, version, err)
		}
	} else if load.Type == "raw_tracepoint" || load.Type == "raw_tp" {
		err = loadInstance(bpfDir, load, maps, version, option.Config.Verbosity)
		if err != nil {
			l.WithField(
				"raw_tracepoint", load.Name,
			).Info("Failed to load, trying to remove and retrying")
			load.Unload(true)
			err = loadInstance(bpfDir, load, maps, version, option.Config.Verbosity)
		}
		if err != nil {
			return fmt.Errorf("failed prog %s kern_version %d LoadRawTracepointProgram: %w",
				load.Name, version, err)
		}
	} else {
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
		logger.GetLogger().WithField("Program", load.Name).
			WithField("Type", load.Type).
			WithField("Attach", load.Attach).
			Debug("Loading BPF program")
		return loadFn(bpfDir, load, maps, verbose)
	}
	// Otherwise, check for a registered probe type. If one exists, use that.
	probe, ok := registeredProbeLoad[load.Type]
	if ok {
		logger.GetLogger().WithField("Program", load.Name).
			WithField("Type", load.Type).
			WithField("Attach", load.Attach).
			Debug("Loading registered BPF probe")
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
		return false, fmt.Errorf("kernel version lookup failed, required for kprobe")
	}
	return true, nil
}
