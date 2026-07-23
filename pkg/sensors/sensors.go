// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package sensors

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/tracingpolicy"

	// load rthooks for policy filter
	_ "github.com/cilium/tetragon/pkg/policyfilter/rthooks"
)

var (
	// allPrograms are all the loaded programs. For use with Unload().
	allPrograms = []*program.Program{}
	// allMaps are all the loaded maps. For use with Unload().
	allMaps = []*program.Map{}
	// protects allPrograms and allMaps
	allProgramsAndMapsMutex sync.Mutex
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
	// Policy namespace the sensor is part of.
	Namespace string
	// Policy name the sensor is part of.
	Policy string
	// When loaded this contains bpffs root directory
	BpfDir string
	// Progs are all the BPF programs that exist on the filesystem.
	Progs []*program.Program
	// Maps are all the BPF Maps that the progs use.
	Maps []*program.Map
	// Loaded indicates whether the sensor has been Loaded.
	Loaded bool
	// Destroyed indicates whether the sensor had been destroyed.
	Destroyed bool
	// PostLoadHook can optionally contain a pointer to a function to be
	// called during sensor loading, after the programs and maps being
	// loaded.
	PostLoadHook SensorHook
	// PostMapLoadHook runs after maps are preloaded and before programs load.
	// Unlike PostLoadHook, an error aborts sensor loading.
	PostMapLoadHook SensorHook
	// PreDisableHook runs before the manager takes its global load lock, for
	// dependent sensors whose teardown re-enters the manager.
	PreDisableHook SensorHook
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
	// DisableNotAllowedReason indicates whether the sensor cannot be disabled.
	// If non-empty, this string is the reason why the sensor cannot be disabled.
	// If empty, the sensor can be disabled.
	DisableNotAllowedReason string
}

// joinHooks composes two sensor hooks: both run and their errors are joined.
func joinHooks(prev, next SensorHook) SensorHook {
	if prev == nil {
		return next
	}
	return func() error {
		return errors.Join(prev(), next())
	}
}

func (s *Sensor) AddPostLoadHook(hook SensorHook) {
	s.PostLoadHook = joinHooks(s.PostLoadHook, hook)
}

// AddPostMapLoadHook composes a fatal map-initialization hook. Later hooks do
// not run if an earlier hook fails.
func (s *Sensor) AddPostMapLoadHook(hook SensorHook) {
	if s.PostMapLoadHook == nil {
		s.PostMapLoadHook = hook
		return
	}

	oldPostMapLoadHook := s.PostMapLoadHook
	s.PostMapLoadHook = func() error {
		if err := oldPostMapLoadHook(); err != nil {
			return err
		}
		return hook()
	}
}

// AddPreDisableHook composes a hook which the manager runs before acquiring
// its global load lock for policy disable.
func (s *Sensor) AddPreDisableHook(hook SensorHook) {
	s.PreDisableHook = joinHooks(s.PreDisableHook, hook)
}

// PreDisable runs the optional pre-disable hook; intentionally not part of
// SensorIface so other implementations need no boilerplate.
func (s *Sensor) PreDisable() error {
	if s.PreDisableHook == nil {
		return nil
	}
	return s.PreDisableHook()
}

// AddPreUnloadHook composes a hook to run before the sensor's programs and
// maps are unloaded.
func (s *Sensor) AddPreUnloadHook(hook SensorHook) {
	s.PreUnloadHook = joinHooks(s.PreUnloadHook, hook)
}

func (s *Sensor) AddPostUnloadHook(hook SensorHook) {
	s.PostUnloadHook = joinHooks(s.PostUnloadHook, hook)
}

type Prog struct {
	Namespace string
	Policy    string
	Sensor    string
	Attach    string
	Label     string
}

type ProgOverhead struct {
	Prog
	RunTime time.Duration
	RunCnt  uint64
}

// SensorIface is an interface for sensors.Sensor that allows implementing sensors for testing.
type SensorIface interface {
	GetName() string
	IsLoaded() bool
	Load(bpfDir string) error
	Unload(unpin bool) error
	Destroy(unpin bool) error
	// TotalMemlock is the total amount of memlock bytes for BPF maps used by
	// the sensor's programs.
	TotalMemlock() uint64
	Overhead() ([]ProgOverhead, bool)
	DisableNotAllowed() string
}

func (s *Sensor) Overhead() ([]ProgOverhead, bool) {
	var list []ProgOverhead

	for _, p := range s.Progs {
		if p.Prog == nil {
			continue
		}
		stats, err := p.Prog.Stats()
		if err != nil {
			continue
		}

		list = append(list, ProgOverhead{
			Prog: Prog{
				Attach: p.Attach,
				Label:  p.Label,
				Sensor: s.Name,
			},
			RunTime: stats.Runtime,
			RunCnt:  stats.RunCount,
		})
	}
	return list, len(list) != 0
}

func (s *Sensor) GetName() string {
	return s.Name
}

func (s *Sensor) IsLoaded() bool {
	return s.Loaded
}

func (s *Sensor) DisableNotAllowed() string {
	return s.DisableNotAllowedReason
}

func (s Sensor) TotalMemlock() uint64 {
	uniqueMap := map[int]bpf.ExtendedMapInfo{}
	for _, p := range s.Progs {
		// we could first check that it exist then write but all maps with
		// same ID on the kernel should share the same info.
		p.CopyLoadedMapsInfo(uniqueMap)
	}

	var total uint64
	for _, info := range uniqueMap {
		// we are using info.Name that is truncated to 15 chars to exclude
		// global maps, a more resilient implementation could use ID but this
		// should be enough.
		if program.IsGlobalMap(info.Name) {
			continue
		}
		total += info.Memlock
	}

	return total
}

// SensorHook is the function signature for an optional function
// that can be called during sensor unloading and removing.
type SensorHook func() error

func SensorCombine(tp tracingpolicy.TracingPolicy, name string, sensors ...*Sensor) *Sensor {
	progs := []*program.Program{}
	maps := []*program.Map{}
	for _, s := range sensors {
		progs = append(progs, s.Progs...)
		maps = append(maps, s.Maps...)
	}
	return SensorBuilder(tp, name, progs, maps)
}

func SensorBuilder(tp tracingpolicy.TracingPolicy, name string, p []*program.Program, m []*program.Map) *Sensor {
	return &Sensor{
		Name:      name,
		Progs:     p,
		Maps:      m,
		Policy:    tp.TpName(),
		Namespace: tp.TpNamespace(),
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
	logger.GetLogger().Debug("Registered probe type", "probeType", probeType, "sensors", s)
	if _, exists := registeredProbeLoad[probeType]; exists {
		panic(fmt.Sprintf("RegisterProbeType called, but %s is already registered", probeType))
	}
	registeredProbeLoad[probeType] = s
}

// LoadProbeArgs are the args to the LoadProbe function.
type LoadProbeArgs struct {
	BPFDir           string
	Load             *program.Program
	Maps             []*program.Map
	Version, Verbose int
}

func addProgsAndMaps(progs []*program.Program, maps []*program.Map) {
	allProgramsAndMapsMutex.Lock()
	defer allProgramsAndMapsMutex.Unlock()

	allPrograms = append(allPrograms, progs...)
	allMaps = append(allMaps, maps...)
}

func cleanupProgsAndMaps() {
	allProgramsAndMapsMutex.Lock()
	defer allProgramsAndMapsMutex.Unlock()

	maps := []*program.Map{}

	for _, m := range allMaps {
		if m.PinState.IsLoaded() {
			maps = append(maps, m)
		}
	}

	allMaps = maps

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

func AllMaps() []*program.Map {
	return append([]*program.Map{}, allMaps...)
}

// sortSensors sort the sensors to enforce orderging constrains.
//
// resolvePathInContainer teardown (uprobe_ric_linux.go) may re-enter the
// manager from load-rollback hooks and is safe only while "generic_uprobe"
// sorts after every sibling that can fail to load. Today that holds because
// policies are single-section ("__enforcer__" is sorted first and never
// last); TestSortSensorsGenericUprobeLast guards it.
func sortSensors(sensors []SensorIface) {
	sort.Slice(sensors, func(i, j int) bool {
		iName := sensors[i].GetName()
		if iName == "__enforcer__" {
			return true
		}
		jName := sensors[j].GetName()
		if jName == "__enforcer__" {
			return false
		}
		return iName < jName
	})
}
