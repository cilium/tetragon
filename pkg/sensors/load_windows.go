// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package sensors

import (
	"fmt"

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

	if err = s.FindPrograms(); err != nil {
		return fmt.Errorf("tetragon, aborting could not find BPF programs: %w", err)
	}
	// Comparing with Linux, why are maps not loaded here ?
	// In windows, we load collection directly and do not load specs.
	// The collection loads maps for us.
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

	l.WithFields(logrus.Fields{
		"sensor": s.Name,
		"maps":   loadedMaps,
		"progs":  loadedProgs,
	}).Infof("Loaded BPF maps and events for sensor successfully")
	s.Loaded = true
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

	err = loadInstance(bpfDir, load, maps, version, option.Config.Verbosity)
	if err != nil && load.ErrorFatal {
		return fmt.Errorf("failed prog %s kern_version %d loadInstance: %w",
			load.Name, version, err)
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

	return fmt.Errorf("program %s has unregistered type '%s'", load.Label, load.Type)
}

func observerMinReqs() (bool, error) {
	return true, nil
}
