// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package sensors

import (
	"fmt"
	"sync"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/sensors/program/cgroup"
	"github.com/cilium/tetragon/pkg/tracingpolicy"

	// load rthooks for policy filter
	_ "github.com/cilium/tetragon/pkg/policyfilter/rthooks"
)

var (
	// allPrograms are all the loaded programs. For use with Unload().
	allPrograms = []*program.Program{}
	// allPrograms lock
	allProgramsMutex sync.Mutex
	// AllMaps are all the loaded programs. For use with Unload().
	AllMaps = []*program.Map{}
)

// Sensors
//
// Sensors are a mechanism for dynamically loading/unloading bpf programs.
// Contrarily to low-level facilities like kprobes, sensors are meant to be
// visible to end users who can enable/disable them.
//
// Sensor control operations are done in a separate goroutine which acts as a
// serialization point for concurrent client requests.

// Sensor is a set of BPF programs and maps that are managed as a unit.
type Sensor struct {
	// Name is a human-readbale description.
	Name string
	// Policy name the sensor is part of.
	Policy string
	// Progs are all the BPF programs that exist on the filesystem.
	Progs []*program.Program
	// Maps are all the BPF Maps that the progs use.
	Maps []*program.Map
	// Loaded indicates whether the sensor has been Loaded.
	Loaded bool
	// Destroyed indicates whether the sensor had been destroyed.
	Destroyed bool
	// PreUnloadHook can optionally contain a pointer to a function to be
	// called during sensor unloading, prior to the programs and maps being
	// unloaded.
	PreUnloadHook SensorHook
	// PostUnloadHook can optionally contain a pointer to a function to be
	// called during sensor unloading, after the programs and maps being
	// unloaded.
	PostUnloadHook SensorHook
	// DestroyHook can optionally contain a pointer to a function to be called
	// when removing the sensor, sensor cannot be loaded again after this hook
	// being triggered and must be recreated.
	DestroyHook SensorHook
}

// SensorIface is an interface for sensors.Sensor that allows implementing sensors for testing.
type SensorIface interface {
	GetName() string
	IsLoaded() bool
	Load(bpfDir string) error
	Unload() error
	Destroy()
}

func (s *Sensor) GetName() string {
	return s.Name
}

func (s *Sensor) IsLoaded() bool {
	return s.Loaded
}

// SensorHook is the function signature for an optional function
// that can be called during sensor unloading and removing.
type SensorHook func() error

func SensorCombine(name string, sensors ...*Sensor) *Sensor {
	progs := []*program.Program{}
	maps := []*program.Map{}
	for _, s := range sensors {
		progs = append(progs, s.Progs...)
		maps = append(maps, s.Maps...)
	}
	return SensorBuilder(name, progs, maps)
}

func SensorBuilder(name string, p []*program.Program, m []*program.Map) *Sensor {
	return &Sensor{
		Name:  name,
		Progs: p,
		Maps:  m,
	}
}

type policyHandler interface {
	// PolicyHandler returns a Sensor for a given policy
	// sensors that support policyfilter can use the filterID to implement filtering.
	// sensors that do not support policyfilter need to return an error if filterID != policyfilter.NoFilterID
	PolicyHandler(policy tracingpolicy.TracingPolicy, filterID policyfilter.PolicyID) (SensorIface, error)
}

type probeLoader interface {
	LoadProbe(args LoadProbeArgs) error
}

var (
	// list of registered policy handlers, see RegisterPolicyHandlerAtInit()
	registeredPolicyHandlers = map[string]policyHandler{}
	// list of registers loaders, see registerProbeType()
	registeredProbeLoad = map[string]probeLoader{}
	standardTypes       = map[string]func(string, *program.Program, int) error{
		"tracepoint":     program.LoadTracepointProgram,
		"raw_tracepoint": program.LoadRawTracepointProgram,
		"raw_tp":         program.LoadRawTracepointProgram,
		"cgrp_socket":    cgroup.LoadCgroupProgram,
		"kprobe":         program.LoadKprobeProgram,
		"lsm":            program.LoadLSMProgram,
	}
)

// RegisterPolicyHandlerAtInit registers a handler for a tracing policy.
func RegisterPolicyHandlerAtInit(name string, h policyHandler) {
	if _, exists := registeredPolicyHandlers[name]; exists {
		panic(fmt.Sprintf("RegisterPolicyHandlerAtInit called, but %s is already registered", name))
	}
	registeredPolicyHandlers[name] = h
}

// RegisterProbeType registers a handler for a probe type string
//
// This function is meant to be called in an init() by sensors that
// need extra logic when loading a specific probe type.
func RegisterProbeType(probeType string, s probeLoader) {
	logger.GetLogger().WithField("probeType", probeType).WithField("sensors", s).Debug("Registered probe type")
	if _, exists := registeredProbeLoad[probeType]; exists {
		panic(fmt.Sprintf("RegisterProbeType called, but %s is already registered", probeType))
	}
	registeredProbeLoad[probeType] = s
}

// LoadProbeArgs are the args to the LoadProbe function.
type LoadProbeArgs struct {
	BPFDir           string
	Load             *program.Program
	Version, Verbose int
}

func GetMergedSensorFromParserPolicy(tp tracingpolicy.TracingPolicy) (SensorIface, error) {
	// NB: use a filter id of 0, so no filtering will happen
	sis, err := SensorsFromPolicy(tp, policyfilter.NoFilterID)
	if err != nil {
		return nil, err
	}
	sensors := make([]*Sensor, 0, len(sis))
	for _, si := range sis {
		s, ok := si.(*Sensor)
		if !ok {
			return nil, fmt.Errorf("cannot merge sensor of type %T", si)
		}
		sensors = append(sensors, s)
	}

	return SensorCombine(tp.TpName(), sensors...), nil
}

func progsAdd(progs []*program.Program) {
	allProgramsMutex.Lock()
	defer allProgramsMutex.Unlock()

	allPrograms = append(allPrograms, progs...)
}

func progsCleanup() {
	allProgramsMutex.Lock()
	defer allProgramsMutex.Unlock()

	progs := []*program.Program{}

	for _, p := range allPrograms {
		if p.LoadState.IsLoaded() {
			progs = append(progs, p)
		}
	}

	allPrograms = progs
}

func AllPrograms() []*program.Program {
	return append([]*program.Program{}, allPrograms...)
}
