// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package sensors

import (
	"fmt"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

var (
	// AllPrograms are all the loaded programs. For use with Unload().
	AllPrograms = []*program.Program{}
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
//
// NB: We need to rethink the Ops field. See manager main loop for some
// discussion on this. If we decide to keep them, we should merge them with the
// UnloadHook since the two are similar: ops.Unloaded is called when a sensor
// is successfully unloaded, while UnloadHook is called during unloading.
type Sensor struct {
	// Name is a human-readbale description.
	Name string
	// Progs are all the BPF programs that exist on the filesystem.
	Progs []*program.Program
	// Maps are all the BPF Maps that the progs use.
	Maps []*program.Map
	// Loaded indicates whether the sensor has been Loaded.
	Loaded bool
	// Ops contains an implementation to perform on this sensor.
	Ops Operations
	// UnloadHook can optionally contain a pointer to a function to be
	// called during sensor unloading, prior to the programs and maps being
	// unloaded.
	UnloadHook SensorUnloadHook
}

// Operations is the interface to the underlying sensor implementations.
type Operations interface {
	Loaded(arg LoadArg)
	Unloaded(arg UnloadArg)

	GetConfig(cfg string) (string, error)
	SetConfig(cfg string, val string) error
}

// SensorUnloadHook is the function signature for an optional function
// that can be called during sensor unloading.
type SensorUnloadHook func() error

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

type specHandler interface {
	SpecHandler(interface{}) (*Sensor, error)
}

type probeLoader interface {
	LoadProbe(args LoadProbeArgs) error
}

var (
	// list of registered Tracing handlers, see registerTracingHandler()
	registeredSpecHandlers = map[string]specHandler{}
	// list of registers loaders, see registerProbeType()
	registeredProbeLoad = map[string]probeLoader{}
)

// RegisterSpecHandlerAtInit registers a handler for Tracing policy.
//
// This function is meant to be called in an init().
// This will register a CRD or config file handler so that the config file
// or CRDs will be passed to the handler to be parsed.
func RegisterSpecHandlerAtInit(name string, s specHandler) {
	if _, exists := registeredSpecHandlers[name]; exists {
		panic(fmt.Sprintf("RegisterTracingSensor called, but %s is already registered", name))
	}
	registeredSpecHandlers[name] = s
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
	BPFDir, MapDir, CiliumDir string
	Load                      *program.Program
	Version, Verbose          int
}

func GetSensorsFromParserPolicy(spec interface{}) ([]*Sensor, error) {
	var sensors []*Sensor
	for _, s := range registeredSpecHandlers {
		sensor, err := s.SpecHandler(spec)
		if err != nil {
			return nil, err
		}
		if sensor == nil {
			continue
		}
		sensors = append(sensors, sensor)
	}
	return sensors, nil
}

func GetMergedSensorFromParserPolicy(name string, policy interface{}) (*Sensor, error) {
	sensors, err := GetSensorsFromParserPolicy(policy)
	if err != nil {
		return nil, err
	}
	return SensorCombine(name, sensors...), nil
}
