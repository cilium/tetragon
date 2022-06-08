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
	loader "github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/btf"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/sensors/program/cgroup"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
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

	logger.GetLogger().WithField("metadata", option.Config.BTF).Info("Using metadata file")
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

	if err := s.LoadMaps(stopCtx, mapDir); err != nil {
		return fmt.Errorf("tetragon, aborting could not load sensor BPF maps: %w", err)
	}

	for _, p := range s.Progs {
		if p.LoadState.IsDisabled() {
			l.WithField("prog", p.Name).Info("BPF prog is disabled, skipping")
			continue
		}

		if p.LoadState.IsLoaded() {
			l.WithField("prog", p.Name).Info("BPF prog is already loaded, incrementing reference count")
			p.LoadState.RefInc()
			continue
		}

		if err := observerLoadInstance(stopCtx, bpfDir, mapDir, ciliumDir, p); err != nil {
			return err
		}
		p.LoadState.RefInc()
		l.WithField("prog", p.Name).WithField("label", p.Label).Info("BPF prog was loaded")
	}
	l.WithField("sensor", s.Name).Infof("Loaded BPF maps and events for sensor successfully")
	s.Loaded = true
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

	if option.Config.IgnoreMissingProgs {
		logger.GetLogger().Warningf("Failed to find BPF prog %s, but was told to ignore such errors. Disabling it and moving on.", p.Name)
		disableBpfLoad(p)
		return nil
	}

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

// LoadMaps loads all the BPF maps in the sensor.
func (s *Sensor) LoadMaps(stopCtx context.Context, mapDir string) error {
	l := logger.GetLogger()
	for _, m := range s.Maps {
		if m.PinState.IsDisabled() {
			l.WithField("map", m.Name).Info("map is disabled, skipping.")
			continue
		}
		if m.PinState.IsLoaded() {
			l.WithFields(logrus.Fields{
				"sensor": s.Name,
				"map":    m.Name,
			}).Info("map is already loaded, incrementing reference count")
			m.PinState.RefInc()
			continue
		}

		pinPath := filepath.Join(mapDir, m.PinName)

		// Try to open the pinPath and if it exist use the previously
		// pinned map otherwise pin the map and next user will find
		// it here.
		if _, err := os.Stat(pinPath); err == nil {
			if err = m.LoadPinnedMap(pinPath); err != nil {
				return fmt.Errorf("loading pinned map failed: %w", err)
			}
		} else {
			spec, err := ebpf.LoadCollectionSpec(m.Prog.Name)
			if err != nil {
				return fmt.Errorf("failed to open collection '%s': %w", m.Prog.Name, err)
			}
			mapSpec, ok := spec.Maps[m.Name]
			if !ok {
				return fmt.Errorf("map '%s' not found from '%s'", m.Name, m.Prog.Name)
			}

			if err := m.New(mapSpec); err != nil {
				return fmt.Errorf("failed to open map '%s': %w", m.Name, err)
			}
			if err := m.Pin(pinPath); err != nil {
				m.Close()
				return fmt.Errorf("failed to pin to %s: %w", pinPath, err)
			}
		}
		m.PinState.RefInc()

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
	var fd int

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
		fd, err = loadInstance(bpfDir, mapDir, ciliumDir, load, version, option.Config.Verbosity)
		if err != nil && fd == -17 { // tracepoint exists be unfriendly and delete it
			l.WithField(
				"tracepoint", load.Name,
			).Info("Tracepoint exists: removing and retrying")
			removeTracepoint(load.TraceFD)
			fd, err = loadInstance(bpfDir, mapDir, ciliumDir, load, version, option.Config.Verbosity)
		}
		if err != nil {
			return fmt.Errorf("failed prog %s kern_version %d err %d LoadTracingProgram: %w",
				load.Name, version, fd, err)
		}
	} else {
		fd, err = loadInstance(bpfDir, mapDir, ciliumDir, load, version, option.Config.Verbosity)
		if err != nil && load.ErrorFatal {
			return fmt.Errorf("failed prog %s kern_version %d LoadKprobeProgram: %w",
				load.Name, version, err)
		}
	}
	load.TraceFD = fd
	return nil
}

func loadInstance(bpfDir, mapDir, ciliumDir string, load *program.Program, version, verbose int) (int, error) {
	version = kernels.FixKernelVersion(version)
	btfObj := uintptr(btf.GetCachedBTF())
	if load.Type == "tracepoint" {
		return loader.LoadTracingProgram(
			version, verbose,
			btfObj,
			load.Name,
			load.Attach,
			load.Label,
			filepath.Join(bpfDir, load.PinPath),
			mapDir)
	} else if load.Type == "cgrp_socket" {
		err := cgroup.LoadCgroupProgram(
			bpfDir,
			mapDir,
			ciliumDir,
			load)
		return -1, err
	} else {
		if s, ok := registeredProbeLoad[load.Type]; ok {
			logger.GetLogger().WithField("Program", load.Name).WithField("Type", load.Type).Infof("Load probe")
			return s.LoadProbe(LoadProbeArgs{
				BPFDir:    bpfDir,
				MapDir:    mapDir,
				CiliumDir: ciliumDir,
				Load:      load,
				Version:   version,
				Verbose:   verbose,
			})
		}
		return loader.LoadKprobeProgram(
			version, verbose,
			btfObj,
			load.Name,
			load.Attach,
			load.Label,
			filepath.Join(bpfDir, load.PinPath),
			mapDir,
			load.RetProbe)
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

func disableBpfLoad(prog *program.Program) {
	prog.LoadState.SetDisabled()
	for _, om := range AllMaps {
		if om.Prog == prog {
			logger.GetLogger().WithField("map", om.Name).Infof("Disabling map")
			om.PinState.SetDisabled()
		}
	}
}

func removeTracepoint(fd int) {
	if fd > 0 {
		PERF_EVENT_IOC_DISABLE := uint(0x2401)
		err := unix.IoctlSetInt(fd, PERF_EVENT_IOC_DISABLE, 0)
		if err != nil && option.Config.Verbosity > 1 {
			logger.GetLogger().WithError(err).Warnf("Warning failed tracepoint removal")
		}
		unix.Close(fd)
	}
}

func UnloadAll(bpfDir string) {
	for _, l := range AllPrograms {
		RemoveProgram(bpfDir, l)
	}

	for _, m := range AllMaps {
		if err := m.Unload(); err != nil {
			logger.GetLogger().Warnf("Failed to unload map %s: %s", m.Name, err)
		}
	}

	AllPrograms = []*program.Program{}
	AllMaps = []*program.Map{}
}
