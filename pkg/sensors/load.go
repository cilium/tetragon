// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package sensors

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	cachedbtf "github.com/cilium/tetragon/pkg/btf"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/sensors/program/cgroup"

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
func LoadConfig(ctx context.Context, bpfDir, mapDir, ciliumDir string, sens []*Sensor) error {
	load := mergeSensors(sens)
	if err := load.Load(ctx, bpfDir, mapDir, ciliumDir); err != nil {
		return fmt.Errorf("tetragon, aborting could not load BPF programs: %w", err)
	}
	return nil
}

// Load loads the sensor, by loading all the BPF programs and maps.
func (s *Sensor) Load(stopCtx context.Context, bpfDir, mapDir, ciliumDir string) error {
	if s == nil {
		return nil
	}

	// Add the loaded programs and maps to All* so they can be unloaded on shutdown.
	AllPrograms = append(AllPrograms, s.Progs...)
	AllMaps = append(AllMaps, s.Maps...)

	logger.GetLogger().WithField("metadata", cachedbtf.GetCachedBTFFile()).Info("BTF file: using metadata file")
	if _, err := observerMinReqs(stopCtx); err != nil {
		return fmt.Errorf("tetragon, aborting minimum requirements not met: %w", err)
	}

	createDir(bpfDir, mapDir)

	l := logger.GetLogger()

	l.WithField("name", s.Name).Info("Loading sensor")
	if s.Loaded {
		return fmt.Errorf("loading sensor %s failed: sensor already loaded", s.Name)
	}

	_, verStr, _ := kernels.GetKernelVersion(option.Config.KernelVersion, option.Config.ProcFS)
	l.Infof("Loading kernel version %s", verStr)

	if err := s.FindPrograms(stopCtx); err != nil {
		return fmt.Errorf("tetragon, aborting could not find BPF programs: %w", err)
	}

	if err := s.loadMaps(stopCtx, mapDir); err != nil {
		return fmt.Errorf("tetragon, aborting could not load sensor BPF maps: %w", err)
	}

	for _, p := range s.Progs {
		if p.LoadState.IsLoaded() {
			l.WithField("prog", p.Name).Info("BPF prog is already loaded, incrementing reference count")
			p.LoadState.RefInc()
			continue
		}

		if err := observerLoadInstance(stopCtx, bpfDir, mapDir, ciliumDir, p); err != nil {
			return err
		}
		p.LoadState.RefInc()
		l.WithField("prog", p.Name).WithField("label", p.Label).Debugf("BPF prog was loaded")
	}
	l.WithField("sensor", s.Name).Infof("Loaded BPF maps and events for sensor successfully")
	s.Loaded = true
	return nil
}

func (s *Sensor) Unload() error {
	logger.GetLogger().Infof("Unloading sensor %s", s.Name)
	if !s.Loaded {
		return fmt.Errorf("unload of sensor %s failed: sensor not loaded", s.Name)
	}

	if s.UnloadHook != nil {
		if err := s.UnloadHook(); err != nil {
			logger.GetLogger().Warnf("Sensor %s unload hook failed: %s", s.Name, err)
		}
	}

	for _, p := range s.Progs {
		unloadProgram(p)
	}

	for _, m := range s.Maps {
		if err := m.Unload(); err != nil {
			logger.GetLogger().Warnf("Failed to unload map %s: %s", m.Name, err)
		}
	}

	s.Loaded = false
	return nil
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
func (s *Sensor) FindPrograms(ctx context.Context) error {
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

// loadMaps loads all the BPF maps in the sensor.
func (s *Sensor) loadMaps(stopCtx context.Context, mapDir string) error {
	l := logger.GetLogger()
	for _, m := range s.Maps {
		if m.PinState.IsLoaded() {
			l.WithFields(logrus.Fields{
				"sensor": s.Name,
				"map":    m.Name,
			}).Info("map is already loaded, incrementing reference count")
			m.PinState.RefInc()
			continue
		}

		pinPath := filepath.Join(mapDir, m.PinName)

		spec, err := ebpf.LoadCollectionSpec(m.Prog.Name)
		if err != nil {
			return fmt.Errorf("failed to open collection '%s': %w", m.Prog.Name, err)
		}
		mapSpec, ok := spec.Maps[m.Name]
		if !ok {
			return fmt.Errorf("map '%s' not found from '%s'", m.Name, m.Prog.Name)
		}

		if err := m.LoadOrCreatePinnedMap(pinPath, mapSpec); err != nil {
			return fmt.Errorf("failed to load map '%s' for sensor '%s': %w", m.Name, s.Name, err)
		}

		l.WithFields(logrus.Fields{
			"sensor": s.Name,
			"map":    m.Name,
			"path":   pinPath,
		}).Info("tetragon, map loaded.")
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

func observerLoadInstance(stopCtx context.Context, bpfDir, mapDir, ciliumDir string, load *program.Program) error {
	version, _, err := kernels.GetKernelVersion(option.Config.KernelVersion, option.Config.ProcFS)
	if err != nil {
		return err
	}

	l := logger.GetLogger()
	l.WithFields(logrus.Fields{
		"prog":         load.Name,
		"kern_version": version,
	}).Debug("observerLoadInstance", load.Name, version)
	if load.Type == "tracepoint" {
		err = loadInstance(bpfDir, mapDir, ciliumDir, load, version, option.Config.Verbosity)
		if err != nil {
			l.WithField(
				"tracepoint", load.Name,
			).Info("Failed to load, trying to remove and retrying")
			load.Unload()
			err = loadInstance(bpfDir, mapDir, ciliumDir, load, version, option.Config.Verbosity)
		}
		if err != nil {
			return fmt.Errorf("failed prog %s kern_version %d LoadTracingProgram: %w",
				load.Name, version, err)
		}
	} else if load.Type == "raw_tracepoint" || load.Type == "raw_tp" {
		err = loadInstance(bpfDir, mapDir, ciliumDir, load, version, option.Config.Verbosity)
		if err != nil {
			l.WithField(
				"raw_tracepoint", load.Name,
			).Info("Failed to load, trying to remove and retrying")
			load.Unload()
			err = loadInstance(bpfDir, mapDir, ciliumDir, load, version, option.Config.Verbosity)
		}
		if err != nil {
			return fmt.Errorf("failed prog %s kern_version %d LoadRawTracepointProgram: %w",
				load.Name, version, err)
		}
	} else {
		err = loadInstance(bpfDir, mapDir, ciliumDir, load, version, option.Config.Verbosity)
		if err != nil && load.ErrorFatal {
			return fmt.Errorf("failed prog %s kern_version %d LoadKprobeProgram: %w",
				load.Name, version, err)
		}
	}
	return nil
}

func loadInstance(bpfDir, mapDir, ciliumDir string, load *program.Program, version, verbose int) error {
	version = kernels.FixKernelVersion(version)
	probe, ok := registeredProbeLoad[load.Type]
	if ok {
		logger.GetLogger().WithField("Program", load.Name).WithField("Type", load.Type).Info("Loading registered BPF probe")
	} else {
		logger.GetLogger().WithField("Program", load.Name).WithField("Type", load.Type).Info("Loading BPF program")
	}
	if load.Type == "tracepoint" {
		return program.LoadTracepointProgram(bpfDir, mapDir, load, verbose)
	} else if load.Type == "raw_tracepoint" || load.Type == "raw_tp" {
		return program.LoadRawTracepointProgram(bpfDir, mapDir, load, verbose)
	} else if load.Type == "cgrp_socket" {
		return cgroup.LoadCgroupProgram(bpfDir, mapDir, ciliumDir, load, verbose)
	} else if probe != nil {
		// Registered probes need extra setup
		return probe.LoadProbe(LoadProbeArgs{
			BPFDir:    bpfDir,
			MapDir:    mapDir,
			CiliumDir: ciliumDir,
			Load:      load,
			Version:   version,
			Verbose:   verbose,
		})
	} else {
		return program.LoadKprobeProgram(bpfDir, mapDir, load, verbose)
	}
}

func observerMinReqs(ctx context.Context) (bool, error) {
	_, _, err := kernels.GetKernelVersion(option.Config.KernelVersion, option.Config.ProcFS)
	if err != nil {
		return false, fmt.Errorf("kernel version lookup failed, required for kprobe")
	}
	return true, nil
}

func createDir(bpfDir, mapDir string) {
	os.Mkdir(bpfDir, os.ModeDir)
	os.Mkdir(mapDir, os.ModeDir)
}

func unloadProgram(prog *program.Program) {
	log := logger.GetLogger().WithField("label", prog.Label).WithField("pin", prog.PinPath)

	if !prog.LoadState.IsLoaded() {
		log.Debugf("Refusing to remove %s, program not loaded", prog.Label)
		return
	}
	if count := prog.LoadState.RefDec(); count > 0 {
		log.Debugf("Program reference count %d, not unloading yet", count)
		return
	}

	if err := prog.Unload(); err != nil {
		logger.GetLogger().WithField("name", prog.Name).WithError(err).Warn("Failed to unload program")
	}

	log.Info("BPF prog was unloaded")
}

func UnloadAll(bpfDir string) {
	for _, l := range AllPrograms {
		unloadProgram(l)
	}

	for _, m := range AllMaps {
		if err := m.Unload(); err != nil {
			logger.GetLogger().Warnf("Failed to unload map %s: %s", m.Name, err)
		}
	}

	AllPrograms = []*program.Program{}
	AllMaps = []*program.Map{}
}
