// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package sensors

import (
	"fmt"
	"strings"

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
// NB: For now we assume that sensors use disjoint sets of progs and maps.  If
// that assumption breaks, we need to be smarter about loading/deleting programs
// and maps (e.g., keep reference counts).
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
}

// Operations is the interface to the underlying sensor implementations.
type Operations interface {
	Loaded(arg LoadArg)
	Unloaded(arg UnloadArg)

	GetConfig(cfg string) (string, error)
	SetConfig(cfg string, val string) error
}

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

var (
	// list of availableSensors, see registerSensor()
	availableSensors = map[string][]*Sensor{}
	// list of registered Tracing handlers, see registerTracingHandler()
	registeredTracingSensors = map[string]tracingSensor{}
	// list of registers loaders, see registerProbeType()
	registeredProbeLoad = map[string]tracingSensor{}

	manager *Manager
)

// RegisterTracingSensorsAtInit registers a handler for Tracing policy.
//
// This function is meant to be called in an init().
// This will register a CRD or config file handler so that the config file
// or CRDs will be passed to the handler to be parsed.
func RegisterTracingSensorsAtInit(name string, s tracingSensor) {
	if _, exists := availableSensors[name]; exists {
		panic(fmt.Sprintf("RegisterTracingSensor called, but %s is already registered", name))
	}
	registeredTracingSensors[name] = s
}

// RegisterProbeType registers a handler for a probe type string
//
// This function is meant to be called in an init() by sensors that
// need extra logic when loading a specific probe type.
func RegisterProbeType(probeType string, s tracingSensor) {
	logger.GetLogger().WithField("probeType", probeType).WithField("sensors", s).Debug("Registered probe type")
	if _, exists := registeredProbeLoad[probeType]; exists {
		panic(fmt.Sprintf("RegisterProbeType called, but %s is already registered", probeType))
	}
	registeredProbeLoad[probeType] = s
}

func LogRegisteredSensorsAndProbes() {
	log := logger.GetLogger()

	names := []string{}
	for n := range availableSensors {
		names = append(names, n)
	}
	log.WithField("sensors", strings.Join(names, ", ")).Info("Available sensors")

	names = []string{}
	for n := range registeredTracingSensors {
		names = append(names, n)
	}
	log.WithField("sensors", strings.Join(names, ", ")).Info("Registered tracing sensors")

	names = []string{}
	for n := range registeredTracingSensors {
		names = append(names, n)
	}
	log.WithField("types", strings.Join(names, ", ")).Info("Registered probe types")
}

type tracingSensor interface {
	SpecHandler(interface{}) (*Sensor, error)
	LoadProbe(args LoadProbeArgs) error
}

// LoadProbeArgs are the args to the LoadProbe function.
type LoadProbeArgs struct {
	BPFDir, MapDir, CiliumDir string
	Load                      *program.Program
	Version, Verbose          int
}

// registerSensor registers a sensor so that it is available to users.
//
// This function is meant to be called in an init().
// This ensures that the function is called before controller goroutine starts,
// and that the availableSensors is setup without having to worry about
// synchronization.
func RegisterSensorAtInit(s *Sensor) {
	if _, exists := availableSensors[s.Name]; exists {
		panic(fmt.Sprintf("registerSensor called, but %s is already registered", s.Name))
	}

	availableSensors[s.Name] = []*Sensor{s}
}

func GetSensorsFromParserPolicy(spec interface{}) ([]*Sensor, error) {
	var sensors []*Sensor
	for _, s := range registeredTracingSensors {
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
