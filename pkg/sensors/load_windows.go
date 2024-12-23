// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package sensors

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors/program"

	"github.com/sirupsen/logrus"
)

const (
	BPF_PROG_TYPE_UNSPEC                  = 0
	BPF_PROG_TYPE_SOCKET_FILTER           = 1
	BPF_PROG_TYPE_KPROBE                  = 2
	BPF_PROG_TYPE_SCHED_CLS               = 3
	BPF_PROG_TYPE_SCHED_ACT               = 4
	BPF_PROG_TYPE_TRACEPOINT              = 5
	BPF_PROG_TYPE_XDP                     = 6
	BPF_PROG_TYPE_PERF_EVENT              = 7
	BPF_PROG_TYPE_CGROUP_SKB              = 8
	BPF_PROG_TYPE_CGROUP_SOCK             = 9
	BPF_PROG_TYPE_LWT_IN                  = 10
	BPF_PROG_TYPE_LWT_OUT                 = 11
	BPF_PROG_TYPE_LWT_XMIT                = 12
	BPF_PROG_TYPE_SOCK_OPS                = 13
	BPF_PROG_TYPE_SK_SKB                  = 14
	BPF_PROG_TYPE_CGROUP_DEVICE           = 15
	BPF_PROG_TYPE_SK_MSG                  = 16
	BPF_PROG_TYPE_RAW_TRACEPOINT          = 17
	BPF_PROG_TYPE_CGROUP_SOCK_ADDR        = 18
	BPF_PROG_TYPE_LWT_SEG6LOCAL           = 19
	BPF_PROG_TYPE_LIRC_MODE2              = 20
	BPF_PROG_TYPE_SK_REUSEPORT            = 21
	BPF_PROG_TYPE_FLOW_DISSECTOR          = 22
	BPF_PROG_TYPE_CGROUP_SYSCTL           = 23
	BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE = 24
	BPF_PROG_TYPE_CGROUP_SOCKOPT          = 25
	BPF_PROG_TYPE_TRACING                 = 26
	BPF_PROG_TYPE_STRUCT_OPS              = 27
	BPF_PROG_TYPE_EXT                     = 28
	BPF_PROG_TYPE_LSM                     = 29
)

// LoadConfig loads the default sensor, including any from the configuration file.
func LoadConfig(bpfDir string, sens []*Sensor) error {
	return fmt.Errorf("tetragon, aborting could not load BPF programs:")
}

func (s *Sensor) policyDir() string {
	if s.Namespace == "" {
		return sanitize(s.Policy)
	}
	return fmt.Sprintf("%s:%s", s.Namespace, sanitize(s.Policy))
}

func (s *Sensor) createDirs(bpfDir string) {
	for _, p := range s.Progs {
		// setup sensor based program pin path
		p.PinPath = filepath.Join(s.policyDir(), s.Name, p.PinName)
		// and make the path
		if err := os.MkdirAll(filepath.Join(bpfDir, p.PinPath), os.ModeDir); err != nil {
			logger.GetLogger().WithError(err).
				WithField("prog", p.PinName).
				WithField("dir", p.PinPath).
				Warn("Failed to create program dir")
		}
	}
	s.BpfDir = bpfDir
}

func (s *Sensor) removeDirs() {
	// Remove all the program dirs
	for _, p := range s.Progs {
		if err := os.Remove(filepath.Join(s.BpfDir, p.PinPath)); err != nil {
			logger.GetLogger().WithError(err).
				WithField("prog", p.PinName).
				WithField("dir", p.PinPath).
				Warn("Failed to remove program dir")
		}
	}
	// Remove sensor dir
	if err := os.Remove(filepath.Join(s.BpfDir, s.policyDir(), s.Name)); err != nil {
		logger.GetLogger().WithError(err).
			WithField("sensor", s.Name).
			WithField("dir", filepath.Join(s.policyDir(), s.Name)).
			Warn("Failed to remove sensor dir")
	}

	// For policy dir the last one switches off the light.. there still
	// might be other sensors in the policy, so the last sensors removed
	// will succeed in removal policy dir.
	os.Remove(filepath.Join(s.BpfDir, s.policyDir()))
}

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

		if err = observerLoadInstance(bpfDir, p); err != nil {
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

func (s *Sensor) Unload(unpin bool) error {
	logger.GetLogger().Infof("Unloading sensor %s", s.Name)
	if !s.Loaded {
		return fmt.Errorf("unload of sensor %s failed: sensor not loaded", s.Name)
	}

	if s.PreUnloadHook != nil {
		if err := s.PreUnloadHook(); err != nil {
			logger.GetLogger().WithError(err).WithField("sensor", s.Name).Warn("Pre unload hook failed")
		}
	}

	var progs []string
	for _, p := range s.Progs {
		unloadProgram(p, unpin)
		progs = append(progs, p.String())
	}

	var mapsOk, mapsErr []string
	for _, m := range s.Maps {
		if err := m.Unload(unpin); err != nil {
			logger.GetLogger().WithError(err).WithField("map", s.Name).Warn("Failed to unload map")
			mapsErr = append(mapsErr, m.String())
		} else {
			mapsOk = append(mapsOk, m.String())
		}
	}

	if unpin {
		s.removeDirs()
	}

	s.Loaded = false

	if s.PostUnloadHook != nil {
		if err := s.PostUnloadHook(); err != nil {
			logger.GetLogger().WithError(err).WithField("sensor", s.Name).Warn("Post unload hook failed")
		}
	}

	progsCleanup()
	logger.GetLogger().WithFields(logrus.Fields{
		"maps":       mapsOk,
		"maps-error": mapsErr,
		"progs":      progs,
	}).Infof("Sensor unloaded")
	return nil
}

// Destroy will unload the hook and call DestroyHook, this hook is usually used
// to clean up resources that were created during creation of the sensor.
func (s *Sensor) Destroy(unpin bool) {
	err := s.Unload(unpin)
	if err != nil {
		// do not return on error but just log since Unload can only error on
		// sensor being already not loaded
		logger.GetLogger().WithError(err).WithField("sensor", s.Name).Warn("Unload failed during destroy")
	}

	if s.DestroyHook != nil {
		err = s.DestroyHook()
		if err != nil {
			logger.GetLogger().WithError(err).WithField("sensor", s.Name).Warn("Destroy hook failed")
		}
	}
	s.Destroyed = true
}

func (s *Sensor) findProgram(p *program.Program) error {
	logger.GetLogger().WithField("file", p.Name).Debug("Checking for bpf file")
	if _, err := os.Stat(p.Name); err == nil {
		logger.GetLogger().WithField("file", p.Name).Debug("Found bpf file")
		return nil
	}
	logger.GetLogger().WithField("file", p.Name).Debug("Candidate bpf file does not exist")
	last := strings.Split(p.Name, "/")
	filename := last[len(last)-1]

	path := path.Join(option.Config.HubbleLib, filename)
	if _, err := os.Stat(path); err == nil {
		p.Name = path
		logger.GetLogger().WithField("file", path).Debug("Found bpf file")
		return nil
	}
	logger.GetLogger().WithField("file", path).Debug("Candidate bpf file does not exist")

	return fmt.Errorf("sensor program %q can not be found", p.Name)
}

// FindPrograms finds all the BPF programs in the sensor on the filesytem.
func (s *Sensor) FindPrograms() error {
	for _, p := range s.Progs {
		if err := s.findProgram(p); err != nil {
			return err
		}
	}
	for _, m := range s.Maps {
		if err := s.findProgram(m.Prog); err != nil {
			return err
		}
	}
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

func mergeSensors(sensors []*Sensor) *Sensor {
	var progs []*program.Program
	var maps []*program.Map

	for _, s := range sensors {
		progs = append(progs, s.Progs...)
		maps = append(maps, s.Maps...)
	}
	return &Sensor{
		Name:  "__main__",
		Progs: progs,
		Maps:  maps,
	}
}

func observerLoadInstance(bpfDir string, load *program.Program) error {
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
		err = loadInstance(bpfDir, load, version, option.Config.Verbosity)
		if err != nil {
			l.WithField(
				"tracepoint", load.Name,
			).Info("Failed to load, trying to remove and retrying")
			load.Unload(true)
			err = loadInstance(bpfDir, load, version, option.Config.Verbosity)
		}
		if err != nil {
			return fmt.Errorf("failed prog %s kern_version %d LoadTracingProgram: %w",
				load.Name, version, err)
		}
	} else if load.Type == "raw_tracepoint" || load.Type == "raw_tp" {
		err = loadInstance(bpfDir, load, version, option.Config.Verbosity)
		if err != nil {
			l.WithField(
				"raw_tracepoint", load.Name,
			).Info("Failed to load, trying to remove and retrying")
			load.Unload(true)
			err = loadInstance(bpfDir, load, version, option.Config.Verbosity)
		}
		if err != nil {
			return fmt.Errorf("failed prog %s kern_version %d LoadRawTracepointProgram: %w",
				load.Name, version, err)
		}
	} else {
		err = loadInstance(bpfDir, load, version, option.Config.Verbosity)
		if err != nil && load.ErrorFatal {
			return fmt.Errorf("failed prog %s kern_version %d loadInstance: %w",
				load.Name, version, err)
		}
	}
	return nil
}

func loadInstance(bpfDir string, load *program.Program, version, verbose int) error {
	// Check if the load.type is a standard program type. If so, use the standard loader.
	loadFn, ok := standardTypes[load.Type]
	if ok {
		logger.GetLogger().WithField("Program", load.Name).
			WithField("Type", load.Type).
			WithField("Attach", load.Attach).
			Debug("Loading BPF program")
		return loadFn(bpfDir, load, verbose)
	}

	return fmt.Errorf("program %s has unregistered type '%s'", load.Label, load.Type)
}

func observerMinReqs() (bool, error) {
	return true, nil
}

func unloadProgram(prog *program.Program, unpin bool) {
	log := logger.GetLogger().WithField("label", prog.Label).WithField("pin", prog.PinPath)

	if !prog.LoadState.IsLoaded() {
		log.Debugf("Refusing to remove %s, program not loaded", prog.Label)
		return
	}
	if count := prog.LoadState.RefDec(); count > 0 {
		log.Debugf("Program reference count %d, not unloading yet", count)
		return
	}

	if err := prog.Unload(unpin); err != nil {
		logger.GetLogger().WithField("name", prog.Name).WithError(err).Warn("Failed to unload program")
	}

	log.Debug("BPF prog was unloaded")
}

func UnloadSensors(sens []SensorIface) {
	for i := range sens {
		if err := sens[i].Unload(true); err != nil {
			logger.GetLogger().Warnf("Failed to unload sensor: %s", err)
		}
	}
}
