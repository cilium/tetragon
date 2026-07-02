// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows && !nok8s

package tracing

import (
	"maps"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	slimv1 "github.com/cilium/tetragon/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/tetragon/pkg/labels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/manager/events"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors"
)

// ricRegistry is the process-global registry of resolvePathInContainer uprobe
// reconcilers. Pod handlers are registered against it at init (see below).
var ricRegistry = newUprobeReconcilerRegistry()

// ricResync drives the periodic re-attach of containers that were skipped
// because their root could not be resolved yet (e.g. the runtime hook had not
// recorded a RootDir, or a CRI lookup transiently failed). It runs only while
// at least one resolvePathInContainer policy is loaded.
var ricResync = newResyncController(ricResyncInterval)

// ricResyncInterval is how often the resync re-runs CRI discovery to retry
// containers whose root was not resolvable yet.
const ricResyncInterval = 10 * time.Second

// ricGeneration is incremented on every resolvePathInContainer policy load and
// mixed into child sensor names, so an asynchronous teardown of a previous load
// cannot collide on a sensor name with a fresh re-enable of the same policy.
var ricGeneration atomic.Uint64

// setupResolvePathInContainer wires the per-container uprobe reconciler onto
// sensor when any of its uprobes opts into per-container path resolution: a
// PostLoadHook registers the reconciler and snapshots existing containers, and
// a PostUnloadHook unregisters and detaches on policy disable/removal. The
// nok8s build has a no-op stub instead (the feature needs the pod informer).
func setupResolvePathInContainer(sensor *sensors.Sensor, spec *v1alpha1.TracingPolicySpec, polInfo *policyInfo) {
	if !hasResolvePathInContainer(spec) {
		return
	}
	postLoad, postUnload := registerResolvePathInContainer(spec, polInfo)
	if postLoad != nil {
		sensor.AddPostLoadHook(postLoad)
	}
	// Teardown is a PostUnloadHook (not a DestroyHook) so it runs when the
	// policy is disabled (unload) as well as when it is deleted/destroyed;
	// otherwise disabling a policy would leave the per-container child sensors
	// attached.
	if postUnload != nil {
		sensor.AddPostUnloadHook(postUnload)
	}
}

// RegisterResolvePathInContainerPodHandlers wires the resolvePathInContainer uprobe
// pod-event handlers into src. It is called once at startup from main (the
// podhooks global registry was removed in favor of constructor injection) and
// adds no new informer of its own. The handlers are cheap no-ops until a
// resolvePathInContainer policy is loaded and registers a reconciler.
func RegisterResolvePathInContainerPodHandlers(src events.PodEventSource) error {
	return newUprobePodHandlers(ricRegistry).register(src)
}

// policyKey is the registry key for a resolvePathInContainer policy. It is
// namespace-qualified so two policies that share a name across namespaces do
// not collide.
func policyKey(namespace, name string) string {
	return namespace + "/" + name
}

// selectorMatcher builds a podMatcher from a policy's namespace and pod
// selector, using the same selector machinery as policyfilter
// (labels.SelectorFromLabelSelector). A namespaced policy (policyNamespace != "")
// only matches pods in its own namespace, mirroring policyfilter's podMatches —
// without this a TracingPolicyNamespaced with a label-only selector would attach
// child sensors to matching pods in every namespace. A nil selector matches all
// pods in scope (defensive: validation requires a podSelector on
// resolvePathInContainer policies). The selector is compiled once; matching
// builds a label set from the pod's labels (plus the namespace label) per call.
func selectorMatcher(policyNamespace string, sel *slimv1.LabelSelector) podMatcher {
	var selector labels.Selector
	if sel != nil {
		s, err := labels.SelectorFromLabelSelector(sel)
		if err != nil {
			logger.GetLogger().Warn("uprobe resolvePathInContainer: invalid podSelector, matching no pods", logfields.Error, err)
			return func(string, map[string]string) bool { return false }
		}
		selector = s
	}
	return func(namespace string, podLabels map[string]string) bool {
		if policyNamespace != "" && namespace != policyNamespace {
			return false
		}
		if selector == nil {
			return true
		}
		ls := make(labels.Labels, len(podLabels)+1)
		maps.Copy(ls, podLabels)
		ls[labels.K8sPodNamespace] = namespace
		return selector.Match(ls)
	}
}

// registerResolvePathInContainer sets up the per-container reconciler for a
// resolvePathInContainer uprobe policy and returns sensor hooks: a PostLoadHook
// that registers the reconciler and snapshots existing containers, and a
// PostUnloadHook that unregisters and detaches on policy disable/removal. It
// must only be called when hasResolvePathInContainer(spec) is true.
//
// A fresh reconciler and attacher are built on each load so that a disabled
// policy can be re-enabled with clean state. The snapshot runs off the
// sensor-manager load lock (in PostLoadHook we would be holding muLoad, and
// attaching per-container sensors re-enters the manager), so it is scheduled on
// a goroutine.
func registerResolvePathInContainer(spec *v1alpha1.TracingPolicySpec, polInfo *policyInfo) (postLoad, postUnload sensors.SensorHook) {
	// Collect every resolvePathInContainer uprobe in the policy; they are
	// attached together as one per-container child sensor. (The policy handler
	// restricts a policy to a single uprobe section, so these are all the RIC
	// uprobes.) uprobes and targets stay index-aligned.
	var uprobes []*v1alpha1.UProbeSpec
	var targets []ricTarget
	for i := range spec.UProbes {
		if spec.UProbes[i].ResolvePathInContainer {
			uprobes = append(uprobes, &spec.UProbes[i])
			targets = append(targets, ricTarget{path: spec.UProbes[i].Path})
		}
	}
	if len(uprobes) == 0 {
		return nil, nil
	}

	key := policyKey(polInfo.namespace, polInfo.name)
	match := selectorMatcher(polInfo.namespace, spec.PodSelector)

	postLoad = func() error {
		// Without CRI, containers already running at load are neither discovered
		// nor resolvable (only new containers, via runtime hooks). Warn once per
		// load so a silently-empty attach is diagnosable.
		if !option.Config.EnableCRI {
			logger.GetLogger().Warn("uprobe resolvePathInContainer: CRI is disabled; "+
				"only new containers (via runtime hooks) will be traced. "+
				"Containers already running when the policy loads are discovered "+
				"and resolved via CRI — enable --enable-cri to cover them.",
				"policy", key)
		}
		mgr := observer.GetSensorManager()
		gen := ricGeneration.Add(1)
		att := newContainerSensorAttacher(key, polInfo.name, polInfo.namespace, gen, polInfo.policyID, spec, uprobes, mgr, buildContainerUprobeSensor)
		rec := newContainerUprobeReconciler(option.Config.ProcFS, targets, att, resolveContainerRootDir)
		ricRegistry.register(key, rec, match)
		ricResync.ref()
		// snapshot existing matching containers off the load lock (PostLoadHook
		// runs under the sensor-manager load lock and attaching per-container
		// sensors re-enters the manager). Route through the reconciler captured
		// here, not the registry key, so a snapshot still running after a
		// disable/re-enable cannot attach into a newer policy generation.
		go snapshotExistingContainers(key, rec, match)
		return nil
	}
	postUnload = func() error {
		ricRegistry.unregister(key)
		ricResync.unref()
		return nil
	}
	return postLoad, postUnload
}

// snapshotExistingContainers discovers containers that already exist (via CRI)
// and match the policy's pod selector when the policy is loaded, and drives them
// through the reconciler (which resolves each container's root via the runtime
// hook / CRI). Keys match those derived in the pod-event handler
// (podUID/containerID) so a later pod-delete event detaches them.
func snapshotExistingContainers(key string, rec *containerUprobeReconciler, match podMatcher) {
	all := discoverExistingContainers()
	matched := 0
	for _, c := range all {
		if !match(c.Namespace, c.PodLabels) {
			continue
		}
		matched++
		rec.onContainerAdd(containerKey(c.PodUID, c.ID))
	}
	// Make a silently-empty snapshot diagnosable: with CRI disabled (or no
	// matching running containers) this finds nothing, and the policy relies on
	// later pod-add events for new containers.
	logger.GetLogger().Info("uprobe resolvePathInContainer: snapshot of existing containers",
		"policy", key, "cri-containers", len(all), "matched", matched)
}

// resyncAllPolicies re-routes a single CRI discovery snapshot through every
// registered policy. onContainerAdd is idempotent, so already-attached
// containers are skipped (a map lookup, before any resolution); containers
// previously skipped because their root was not resolvable yet attach once the
// runtime hook / CRI can resolve them.
//
// Cost is bounded: each not-yet-attached match does at most one CRI
// ContainerStatus call plus — when the runtime's PID namespace is not procFS's,
// e.g. under kind — one procFS scan to translate the PID (see
// containerHostPID), capped by the attach cap and the per-call timeout. Missed
// ticks coalesce, so a slow resync only delays the next one.
func resyncAllPolicies() {
	for _, c := range discoverExistingContainers() {
		k := containerKey(c.PodUID, c.ID)
		for _, r := range ricRegistry.matchingReconcilers(c.Namespace, c.PodLabels) {
			r.onContainerAdd(k)
		}
	}
}

// resyncController runs resyncAllPolicies on a ticker, but only while at least
// one resolvePathInContainer policy is loaded. ref/unref track that count; the
// goroutine starts on 0->1 and stops on 1->0.
type resyncController struct {
	interval time.Duration
	mu       sync.Mutex
	count    int
	stop     chan struct{}
}

func newResyncController(interval time.Duration) *resyncController {
	return &resyncController{interval: interval}
}

func (c *resyncController) ref() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.count++
	if c.count == 1 {
		stop := make(chan struct{})
		c.stop = stop
		go c.loop(stop)
	}
}

func (c *resyncController) unref() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.count == 0 {
		return
	}
	c.count--
	if c.count == 0 && c.stop != nil {
		close(c.stop)
		c.stop = nil
	}
}

func (c *resyncController) loop(stop <-chan struct{}) {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			resyncAllPolicies()
		}
	}
}
