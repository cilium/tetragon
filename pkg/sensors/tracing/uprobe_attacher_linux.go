// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"crypto/sha256"
	"fmt"
	"path"
	"sync"

	"github.com/cilium/ebpf"

	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

// containerSensorName derives a deterministic sensor name. Inputs are
// length-delimited so key boundaries cannot collide, and generation keeps a
// stale teardown from colliding with a fresh re-enable.
func containerSensorName(policyKey string, generation uint64, containerKey string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%d:%s%d:%d:%s", len(policyKey), policyKey, generation, len(containerKey), containerKey)
	return fmt.Sprintf("generic_uprobe_ric_%x", h.Sum(nil)[:16])
}

// loadedSensor is what the attacher drives; tests fake it.
type loadedSensor interface {
	Load(bpfDir string) error
	Destroy(unpin bool) error
}

type sensorBuilder func(name, attachPath string) (loadedSensor, error)

// containerSensorAttacher loads and unloads the per-container uprobe sensors
// of one policy load. The parent owns them directly rather than registering
// them with the sensor manager, so teardown never re-enters it.
//
// A whole sensor per container stands in for what should be one more link on
// the parent's program: the loader attaches a program's links as a fixed set,
// with no way to add or remove one afterwards.
type containerSensorAttacher struct {
	policyKey  string // namespace-qualified key
	generation uint64 // per-load generation
	bpfDir     string
	build      sensorBuilder

	mu     sync.Mutex
	loaded map[string]loadedSensor // container key -> loaded sensor
}

func newContainerSensorAttacher(policyKey string, generation uint64, bpfDir string, build sensorBuilder) *containerSensorAttacher {
	return &containerSensorAttacher{
		policyKey:  policyKey,
		generation: generation,
		bpfDir:     bpfDir,
		build:      build,
		loaded:     map[string]loadedSensor{},
	}
}

func (a *containerSensorAttacher) Attach(key, attachPath string) error {
	name := containerSensorName(a.policyKey, a.generation, key)

	sensor, err := a.build(name, attachPath)
	if err != nil {
		return fmt.Errorf("building uprobe sensor for %s: %w", key, err)
	}
	if err := sensor.Load(a.bpfDir); err != nil {
		// Release the uprobe table entries and files the build opened.
		if derr := sensor.Destroy(true); derr != nil {
			logger.GetLogger().Debug("uprobe attacher: destroy after load failure",
				logfields.Error, derr, "sensor", name)
		}
		return fmt.Errorf("loading uprobe sensor for %s: %w", key, err)
	}
	a.mu.Lock()
	a.loaded[key] = sensor
	a.mu.Unlock()
	return nil
}

// Detach unloads the sensor loaded for key.
func (a *containerSensorAttacher) Detach(key string) {
	a.mu.Lock()
	sensor, ok := a.loaded[key]
	delete(a.loaded, key)
	a.mu.Unlock()
	if !ok {
		return
	}

	if err := sensor.Destroy(true); err != nil {
		logger.GetLogger().Warn("uprobe attacher: failed to destroy sensor on detach",
			logfields.Error, err, "key", key)
	}
}

// prepareResolvePathInContainerPolicyMaps makes the parent sensor the sole
// owner of policy_conf and selector-stats, and initializes policy_conf.
func prepareResolvePathInContainerPolicyMaps(sensor *sensors.Sensor, polInfo *policyInfo) {
	loadProgName, _ := config.GenericUprobeObjs(false)
	template := program.Builder(
		path.Join(option.Config.HubbleLib, loadProgName),
		"resolvePathInContainer policy maps",
		"",
		"",
		"generic_uprobe",
	).SetPolicy(polInfo.name)

	policyConf := polInfo.policyConfMap(template)
	sensor.Maps = append(sensor.Maps, policyConf, polInfo.selectorStatsMap(template))

	// The parent loads no programs, so the loader never applies this
	// initializer. Run it as the map's own post-create step, which happens
	// before any program loads and whose error aborts the load. This is wider
	// than Validate's documented job of checking an existing map, for want of
	// a map-level initialization hook.
	for _, mapLoad := range template.MapLoad {
		if mapLoad.Name == policyConf.Name {
			policyConf.Validate = func(m *ebpf.Map, _ *ebpf.MapSpec) error {
				return mapLoad.Load(m, policyConf.PinPath)
			}
			break
		}
	}
}

// containerUprobeSpec builds the child-local spec for one resolved binary. It
// keeps the parent's in-container Path so events report it.
func containerUprobeSpec(parentSpec *v1alpha1.TracingPolicySpec, uprobe *v1alpha1.UProbeSpec) *v1alpha1.TracingPolicySpec {
	// Macro expansion mutates Selectors, so never share them.
	child := uprobe.DeepCopy()
	child.ResolvePathInContainer = false

	spec := &v1alpha1.TracingPolicySpec{UProbes: []v1alpha1.UProbeSpec{*child}}
	if parentSpec != nil {
		spec.Options = parentSpec.Options
		spec.SelectorsMacros = parentSpec.SelectorsMacros
		spec.Lists = parentSpec.Lists
	}
	return spec
}

// containerUprobeSensorBuilder builds one sensor per container, sharing the
// parent policyInfo maps.
func containerUprobeSensorBuilder(polInfo *policyInfo, parentSpec *v1alpha1.TracingPolicySpec, uprobe *v1alpha1.UProbeSpec) sensorBuilder {
	return func(name, attachPath string) (loadedSensor, error) {
		sensor, err := createGenericUprobeSensor(containerUprobeSpec(parentSpec, uprobe), name, polInfo, attachPath)
		if err != nil {
			return nil, err
		}
		return sensor, nil
	}
}
