// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"context"
	"crypto/sha256"
	"fmt"
	"path"
	"sync"

	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

// containerSensorName derives a deterministic sensor name. Inputs are
// length-delimited so key boundaries cannot collide; generation changes per
// (re)load so a stale teardown cannot collide with a fresh re-enable.
func containerSensorName(policyKey string, generation uint64, containerKey string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%d:%s%d:%d:%s", len(policyKey), policyKey, generation, len(containerKey), containerKey)
	return fmt.Sprintf("generic_uprobe_ric_%x", h.Sum(nil)[:16])
}

// sensorManager abstracts the subset of sensors.Manager the attacher needs, so
// the attach/detach flow can be exercised with a fake in tests.
type sensorManager interface {
	AddSensor(ctx context.Context, name string, sensor *sensors.Sensor) error
	EnableSensor(ctx context.Context, name string) error
	RemoveSensor(ctx context.Context, name string) error
}

// sensorBuilder builds the sensor for the policy's RIC uprobes resolved inside
// one container; a test seam over containerUprobeSensorBuilder.
type sensorBuilder func(name string, resolved []resolvedUprobe) (*sensors.Sensor, error)

// containerSensorAttacher loads a per-container uprobe sensor via the sensor
// manager and unloads it on detach; one instance per policy load.
type containerSensorAttacher struct {
	policyKey  string // namespace-qualified key, used to derive sensor names
	generation uint64 // per-load generation, mixed into the sensor name
	mgr        sensorManager
	build      sensorBuilder

	// mu guards keyName independent of caller serialization.
	mu      sync.Mutex
	keyName map[string]string // container key -> loaded sensor name
}

func newContainerSensorAttacher(policyKey string, generation uint64, mgr sensorManager, build sensorBuilder) *containerSensorAttacher {
	return &containerSensorAttacher{
		policyKey:  policyKey,
		generation: generation,
		mgr:        mgr,
		build:      build,
		keyName:    map[string]string{},
	}
}

// Attach builds and loads a uprobe sensor for the resolved in-container path.
func (a *containerSensorAttacher) Attach(key string, resolved []resolvedUprobe) error {
	name := containerSensorName(a.policyKey, a.generation, key)

	sensor, err := a.build(name, resolved)
	if err != nil {
		return fmt.Errorf("building uprobe sensor for %s: %w", key, err)
	}

	ctx := context.Background()
	if err := a.mgr.AddSensor(ctx, name, sensor); err != nil {
		return fmt.Errorf("adding uprobe sensor for %s: %w", key, err)
	}
	if err := a.mgr.EnableSensor(ctx, name); err != nil {
		// best-effort cleanup so the added sensor does not leak.
		if rerr := a.mgr.RemoveSensor(ctx, name); rerr != nil {
			logger.GetLogger().Warn("uprobe attacher: failed to remove sensor after enable failure",
				logfields.Error, rerr, "sensor", name)
		}
		return fmt.Errorf("enabling uprobe sensor for %s: %w", key, err)
	}
	a.mu.Lock()
	a.keyName[key] = name
	a.mu.Unlock()
	return nil
}

// Detach removes the sensor loaded for key. RemoveSensor's destroy unloads
// it; disabling first would make that unload fail with "sensor not loaded".
func (a *containerSensorAttacher) Detach(key string) {
	a.mu.Lock()
	name, ok := a.keyName[key]
	if ok {
		delete(a.keyName, key)
	}
	a.mu.Unlock()
	if !ok {
		return
	}

	if err := a.mgr.RemoveSensor(context.Background(), name); err != nil {
		logger.GetLogger().Warn("uprobe attacher: failed to remove sensor on detach",
			logfields.Error, err, "sensor", name)
	}
}

// prepareResolvePathInContainerPolicyMaps makes the parent sensor the sole
// owner of policy_conf and selector-stats; the returned hook initializes
// policy_conf after the maps load and before any child sensor registers.
func prepareResolvePathInContainerPolicyMaps(sensor *sensors.Sensor, polInfo *policyInfo) sensors.SensorHook {
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

	var initialize *program.MapLoad
	for _, mapLoad := range template.MapLoad {
		if mapLoad.Name == policyConf.Name {
			initialize = mapLoad
			break
		}
	}
	return func() error {
		if initialize == nil || policyConf.MapHandle == nil {
			return fmt.Errorf("resolvePathInContainer policy map %s is not loaded", policyConf.Name)
		}
		return initialize.Load(policyConf.MapHandle, policyConf.PinPath)
	}
}

// containerUprobeSpec builds the child-local spec and attach metadata.
// selectorStatsBases is the parent layout so child stats keep their offsets in
// the parent policy-wide map; uprobes is index-aligned with the parent spec.
func containerUprobeSpec(parentSpec *v1alpha1.TracingPolicySpec, uprobes []*v1alpha1.UProbeSpec, selectorStatsBases []uint32, resolved []resolvedUprobe) (*v1alpha1.TracingPolicySpec, map[int]uprobeAttachOverride, error) {
	childUprobes := make([]v1alpha1.UProbeSpec, len(resolved))
	attachOverrides := make(map[int]uprobeAttachOverride, len(resolved))
	for i := range resolved {
		targetIndex := resolved[i].targetIndex
		if targetIndex < 0 || targetIndex >= len(uprobes) {
			return nil, nil, fmt.Errorf("resolved uprobe target index %d out of range", targetIndex)
		}
		// Macro expansion mutates Selectors, so never share them with the
		// parent policy or another child.
		child := uprobes[targetIndex].DeepCopy()
		child.ResolvePathInContainer = false
		childUprobes[i] = *child
		var statsBase uint32
		if targetIndex < len(selectorStatsBases) {
			statsBase = selectorStatsBases[targetIndex]
		}
		attachOverrides[i] = uprobeAttachOverride{
			attachPath:        resolved[i].attachPath,
			selectorStatsBase: statsBase,
		}
	}

	spec := &v1alpha1.TracingPolicySpec{UProbes: childUprobes}
	if parentSpec != nil {
		spec.Options = parentSpec.Options
		spec.SelectorsMacros = parentSpec.SelectorsMacros
		spec.Lists = parentSpec.Lists
	}
	return spec, attachOverrides, nil
}

// containerUprobeSensorBuilder returns the default sensorBuilder: one sensor
// per policy-spec/inode pair, reporting the in-container Path and attaching
// via the resolved override. Children share the parent policyInfo maps.
func containerUprobeSensorBuilder(polInfo *policyInfo, parentSpec *v1alpha1.TracingPolicySpec, uprobes []*v1alpha1.UProbeSpec) sensorBuilder {
	// The parent layout is fixed for the policy's lifetime; compute it once.
	selectorStatsBases := uprobeSelectorStatsBases(parentSpec)
	return func(name string, resolved []resolvedUprobe) (*sensors.Sensor, error) {
		spec, attachOverrides, err := containerUprobeSpec(parentSpec, uprobes, selectorStatsBases, resolved)
		if err != nil {
			return nil, err
		}
		return createGenericUprobeSensor(spec, name, polInfo, attachOverrides)
	}
}
