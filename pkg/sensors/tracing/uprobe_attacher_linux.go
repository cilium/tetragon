// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"time"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors"
)

// attachTimeout is the timeout on the context passed to each sensor-manager
// call. NOTE: the sensor manager does not currently observe this context for the
// BPF load/unload itself (pkg/sensors/handler.go stores op.ctx but the enable/
// add/remove paths do not select on it), so a wedged load/unload can still block
// the calling goroutine — and, since onContainerAdd/onContainerDel run the
// attach/detach under the reconciler lock, the policy's other container churn —
// beyond this bound. It is a best-effort limit and a forward-looking hook for
// when the manager becomes context-aware; bounding the fan-out properly would
// need a bounded work queue off the pod-event path.
const attachTimeout = 30 * time.Second

// containerSensorName derives a unique, deterministic sensor name for the
// uprobe attached for (policyKey, generation, containerKey). It is collision-free
// across key boundaries: the inputs are length-delimited before hashing so that
// e.g. ("a","b/c") and ("a/b","c") map to different names. policyKey is the
// namespace-qualified policy key, so policies that share a name across
// namespaces get distinct sensor names. generation changes on each policy
// (re)load so an asynchronous teardown of an old load cannot collide on a name
// with a fresh re-enable of the same policy.
func containerSensorName(policyKey string, generation uint64, containerKey string) string {
	h := sha256.New()
	// All fields are length- or separator-delimited so distinct inputs cannot
	// alias (e.g. generation and len(containerKey) are ":"-separated, not adjacent
	// digits).
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

// sensorBuilder builds a *sensors.Sensor for the policy's RIC uprobes resolved
// inside one container (resolved is index-aligned with uprobes). It is a seam so
// the build can be swapped in tests; the default builds a generic uprobe sensor
// scoped to the policy via its policyfilter id. parentSpec is the policy's spec,
// used to carry over policy-wide settings (options, selector macros, lists).
type sensorBuilder func(policyName, namespace, name string, resolved []resolvedUprobe, policyID policyfilter.PolicyID, parentSpec *v1alpha1.TracingPolicySpec, uprobes []*v1alpha1.UProbeSpec) (*sensors.Sensor, error)

// containerSensorAttacher is the real Attacher: it builds a per-container
// uprobe sensor for the policy's RIC uprobes resolved in that container and
// loads it via the sensor manager, unloading it on detach. One instance per
// resolvePathInContainer uprobe policy load.
type containerSensorAttacher struct {
	policyKey  string // namespace-qualified key, used to derive sensor names
	policyName string // policy name, for event attribution in the child sensor
	namespace  string // policy namespace, propagated to the child sensor
	generation uint64 // per-load generation, mixed into the sensor name
	policyID   policyfilter.PolicyID
	parentSpec *v1alpha1.TracingPolicySpec
	uprobes    []*v1alpha1.UProbeSpec // the policy's RIC uprobes
	mgr        sensorManager
	build      sensorBuilder

	// mu guards keyName. The reconciler currently serializes Attach/Detach for
	// a given key, but the attacher is shared state and keeps its own lock so
	// it is correct independent of caller serialization.
	mu      sync.Mutex
	keyName map[string]string // container key -> loaded sensor name
}

func newContainerSensorAttacher(policyKey, policyName, namespace string, generation uint64, policyID policyfilter.PolicyID, parentSpec *v1alpha1.TracingPolicySpec, uprobes []*v1alpha1.UProbeSpec, mgr sensorManager, build sensorBuilder) *containerSensorAttacher {
	return &containerSensorAttacher{
		policyKey:  policyKey,
		policyName: policyName,
		namespace:  namespace,
		generation: generation,
		policyID:   policyID,
		parentSpec: parentSpec,
		uprobes:    uprobes,
		mgr:        mgr,
		build:      build,
		keyName:    map[string]string{},
	}
}

// Attach builds and loads a uprobe sensor for the resolved in-container path.
func (a *containerSensorAttacher) Attach(key string, resolved []resolvedUprobe) error {
	name := containerSensorName(a.policyKey, a.generation, key)

	sensor, err := a.build(a.policyName, a.namespace, name, resolved, a.policyID, a.parentSpec, a.uprobes)
	if err != nil {
		return fmt.Errorf("building uprobe sensor for %s: %w", key, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), attachTimeout)
	defer cancel()
	if err := a.mgr.AddSensor(ctx, name, sensor); err != nil {
		return fmt.Errorf("adding uprobe sensor for %s: %w", key, err)
	}
	if err := a.mgr.EnableSensor(ctx, name); err != nil {
		// best-effort cleanup of the added-but-not-enabled sensor, on a fresh
		// context: if EnableSensor failed because ctx hit its deadline, reusing
		// ctx for RemoveSensor would fail immediately and leak the added sensor.
		rmCtx, rmCancel := context.WithTimeout(context.Background(), attachTimeout)
		defer rmCancel()
		if rerr := a.mgr.RemoveSensor(rmCtx, name); rerr != nil {
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

// Detach removes the uprobe sensor previously loaded for key. RemoveSensor
// destroys the collection, which unloads the still-loaded sensor as part of the
// destroy — the same direct-destroy path deleteTracingPolicy uses. Disabling
// first would unload it, then the destroy's unload would fail with "sensor not
// loaded".
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

	ctx, cancel := context.WithTimeout(context.Background(), attachTimeout)
	defer cancel()
	if err := a.mgr.RemoveSensor(ctx, name); err != nil {
		logger.GetLogger().Warn("uprobe attacher: failed to remove sensor on detach",
			logfields.Error, err, "sensor", name)
	}
}

// buildContainerUprobeSensor is the default sensorBuilder. It builds one
// (multi-)uprobe sensor for the policy's RIC uprobes resolved in a container:
// each uprobe's in-container Path is kept as the reported path, while its
// resolved binary/BTF paths are passed as per-uprobe attach overrides. Policy
// options, macros, lists and policyID are carried over from the parent.
func buildContainerUprobeSensor(policyName, namespace, name string, resolved []resolvedUprobe, policyID policyfilter.PolicyID, parentSpec *v1alpha1.TracingPolicySpec, uprobes []*v1alpha1.UProbeSpec) (*sensors.Sensor, error) {
	childUprobes := make([]v1alpha1.UProbeSpec, len(uprobes))
	attachPaths := make(map[int]string, len(uprobes))
	for i, u := range uprobes {
		// Deep copy: macro expansion mutates Selectors in place, so a shallow
		// copy would corrupt the shared parent uprobe across per-container attaches.
		c := u.DeepCopy()
		c.ResolvePathInContainer = false
		childUprobes[i] = *c
		attachPaths[i] = resolved[i].attachPath
	}

	spec := &v1alpha1.TracingPolicySpec{
		UProbes: childUprobes,
	}
	if parentSpec != nil {
		spec.Options = parentSpec.Options
		spec.SelectorsMacros = parentSpec.SelectorsMacros
		spec.Lists = parentSpec.Lists
	}

	polInfo, err := newPolicyInfoFromSpec(namespace, policyName, policyID, spec, nil)
	if err != nil {
		return nil, err
	}
	return createGenericUprobeSensor(spec, name, polInfo, attachPaths)
}
