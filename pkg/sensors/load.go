// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package sensors

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
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
