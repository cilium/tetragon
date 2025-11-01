// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package sensors

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
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
	load := mergeSensors(sens)
	if err := load.Load(bpfDir); err != nil {
		return fmt.Errorf("tetragon, aborting could not load BPF programs: %w", err)
	}
	return nil
}

func (s *Sensor) policyDir() string {
	return tracingpolicy.PolicyDir(s.Namespace, s.Policy)
}

func (s *Sensor) createDirs(bpfDir string) {
	for _, p := range s.Progs {
		// setup sensor based program pin path if it's not specified
		if p.PinPath == "" {
			p.PinPath = filepath.Join(s.policyDir(), s.Name, p.PinName)
		}
		// and make the path
		if err := os.MkdirAll(filepath.Join(bpfDir, p.PinPath), os.ModeDir); err != nil {
			logger.GetLogger().Warn("Failed to create program dir",
				"prog", p.PinName, "dir", p.PinPath, logfields.Error, err)
		}
	}
	s.BpfDir = bpfDir
}

func (s *Sensor) removeDirs() {
	// Remove all the program dirs
	for _, p := range s.Progs {
		if err := os.Remove(filepath.Join(s.BpfDir, p.PinPath)); err != nil {
			logger.GetLogger().Warn("Failed to remove program dir", "prog", p.PinName, "dir", p.PinPath, logfields.Error, err)
		}
	}
	// Remove sensor dir
	if err := os.Remove(filepath.Join(s.BpfDir, s.policyDir(), s.Name)); err != nil {
		logger.GetLogger().Warn("Failed to remove sensor dir",
			logfields.Error, err, "sensor", s.Name, "dir", filepath.Join(s.policyDir(), s.Name))
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

	logger.GetLogger().Info("BTF file: using metadata file", "metadata", getCachedBTFFile())
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

	l.Info("Loading sensor", "name", s.Name)
	if s.Loaded {
		return fmt.Errorf("loading sensor %s failed: sensor already loaded", s.Name)
	}

	_, verStr, _ := kernels.GetKernelVersion(option.Config.KernelVersion, option.Config.ProcFS)
	l.Info("Loading kernel version " + verStr)

	if err = s.FindPrograms(); err != nil {
		return fmt.Errorf("tetragon, aborting could not find BPF programs: %w", err)
	}
	if loadedMaps, err = s.preLoadMaps(bpfDir, loadedMaps); err != nil {
		return err
	}
	for _, p := range s.Progs {
		if p.LoadState.IsLoaded() {
			l.Info("BPF prog is already loaded, incrementing reference count", "prog", p.Name)
			p.LoadState.RefInc()
			continue
		}

		if err = observerLoadInstance(bpfDir, p, s.Maps); err != nil {
			return err
		}
		p.LoadState.RefInc()
		loadedProgs = append(loadedProgs, p)
		l.Debug("BPF prog was loaded", "prog", p.Name, "label", p.Label)
	}

	// Add the *loaded* programs and maps, so they can be unloaded later
	addProgsAndMaps(s.Progs, s.Maps)

	if s.PostLoadHook != nil {
		if err := s.PostLoadHook(); err != nil {
			logger.GetLogger().Warn("Post load hook failed", "sensor", s.Name, logfields.Error, err)
		}
	}

	// cleanup the BTF once we have loaded all sensor's program
	flushKernelSpec()

	l.Info("Loaded sensor successfully", "sensor", s.Name)
	l.Debug("Loaded sensor BPF maps and programs", "sensor", s.Name, "maps", loadedMaps, "progs", loadedProgs)
	s.Loaded = true
	return nil
}

func (s *Sensor) Unload(unpin bool) error {
	logger.GetLogger().Info("Unloading sensor " + s.Name)
	if !s.Loaded {
		return fmt.Errorf("unload of sensor %s failed: sensor not loaded", s.Name)
	}

	if s.PreUnloadHook != nil {
		if err := s.PreUnloadHook(); err != nil {
			logger.GetLogger().Warn("Pre unload hook failed", "sensor", s.Name, logfields.Error, err)
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
			logger.GetLogger().Warn("Failed to unload map", "map", s.Name, logfields.Error, err)
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
			logger.GetLogger().Warn("Post unload hook failed", "sensor", s.Name, logfields.Error, err)
		}
	}

	cleanupProgsAndMaps()
	logger.GetLogger().Info("Sensor unloaded", "sensor", s.Name, "maps-error", mapsErr)
	logger.GetLogger().Debug("Sensor unloaded additional info", "maps", mapsOk, "maps-error", mapsErr, "progs", progs)
	return nil
}

// Destroy will unload the hook and call DestroyHook, this hook is usually used
// to clean up resources that were created during creation of the sensor.
func (s *Sensor) Destroy(unpin bool) {
	err := s.Unload(unpin)
	if err != nil {
		// do not return on error but just log since Unload can only error on
		// sensor being already not loaded
		logger.GetLogger().Warn("Unload failed during destroy", "sensor", s.Name, logfields.Error, err)
	}

	if s.DestroyHook != nil {
		err = s.DestroyHook()
		if err != nil {
			logger.GetLogger().Warn("Destroy hook failed", "sensor", s.Name, logfields.Error, err)
		}
	}
	s.Destroyed = true
}

func (s *Sensor) findProgram(p *program.Program) error {
	pathname, err := config.FindProgramFile(p.Name)
	if err != nil {
		return err
	}
	p.Name = pathname
	return nil
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

func unloadProgram(prog *program.Program, unpin bool) {
	log := logger.GetLogger().With("label", prog.Label, "pin", prog.PinPath)

	if !prog.LoadState.IsLoaded() {
		log.Debug(fmt.Sprintf("Refusing to remove %s, program not loaded", prog.Label))
		return
	}
	if count := prog.LoadState.RefDec(); count > 0 {
		log.Debug(fmt.Sprintf("Program reference count %d, not unloading yet", count))
		return
	}

	if err := prog.Unload(unpin); err != nil {
		logger.GetLogger().Warn("Failed to unload program", "name", prog.Name, logfields.Error, err)
	}

	log.Debug("BPF prog was unloaded")
}

func UnloadSensors(sens []SensorIface) {
	for i := range sens {
		if err := sens[i].Unload(true); err != nil {
			logger.GetLogger().Warn("Failed to unload sensor", logfields.Error, err)
		}
	}
}
