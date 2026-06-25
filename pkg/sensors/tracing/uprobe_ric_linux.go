// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows && !nok8s

package tracing

import (
	"errors"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/cilium/tetragon/pkg/cri"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	slimv1 "github.com/cilium/tetragon/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/tetragon/pkg/labels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/manager/events"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/podhelpers"
	"github.com/cilium/tetragon/pkg/sensors"
)

// ricRegistry is the process-global registry of resolvePathInContainer uprobe
// reconcilers.
var ricRegistry = newUprobeReconcilerRegistry()

var errRICPodListerUnavailable = errors.New("pod event source does not expose informer snapshots")

// ricPods exposes the current informer cache to snapshot/resync. The event
// source is registered once at startup, before any policy can load.
var ricPods struct {
	sync.RWMutex
	lister events.PodLister
}

// ricResyncInterval is how often the resync retries unresolved containers.
const ricResyncInterval = 10 * time.Second

// ricGeneration is mixed into child sensor names on each policy load so an
// async teardown of a previous load cannot collide with a fresh re-enable.
var ricGeneration atomic.Uint64

// setupResolvePathInContainer wires the per-container reconciler onto sensor:
// the parent owns policy maps before PostLoad registers child sensors, and
// PreUnload removes children while those maps remain pinned. nok8s stubs it.
func setupResolvePathInContainer(sensor *sensors.Sensor, spec *v1alpha1.TracingPolicySpec, polInfo *policyInfo) {
	if !hasResolvePathInContainer(spec) {
		return
	}
	initializePolicyMaps := prepareResolvePathInContainerPolicyMaps(sensor, polInfo)
	postLoad, preUnload := registerResolvePathInContainer(spec, polInfo)
	sensor.AddPostMapLoadHook(initializePolicyMaps)
	if postLoad != nil {
		sensor.AddPostLoadHook(postLoad)
	}
	if preUnload != nil {
		// Disable runs this before the manager's load lock; PreUnload is the
		// idempotent fallback for delete and load errors. PreUnload also fires
		// from collection.load()'s rollback under muLoad — safe only because
		// "generic_uprobe" sorts last in its collection (see sortSensors), so
		// no sibling can fail after this one loads. Keep that ordering.
		sensor.AddPreDisableHook(preUnload)
		sensor.AddPreUnloadHook(preUnload)
	}
}

// RegisterResolvePathInContainerPodHandlers wires the pod-event handlers into
// src and retains its informer snapshot interface. Called once at startup;
// handlers are cheap no-ops until a resolvePathInContainer policy registers a
// reconciler, and the resync loop starts lazily on the first registration.
func RegisterResolvePathInContainerPodHandlers(src events.PodEventSource) error {
	lister, ok := src.(events.PodLister)
	if !ok {
		return errRICPodListerUnavailable
	}
	if err := newUprobePodHandlers(ricRegistry).register(src); err != nil {
		return err
	}
	ricPods.Lock()
	ricPods.lister = lister
	ricPods.Unlock()
	return nil
}

// ricResyncOnce starts the resync loop on the first policy registration, so
// agents that never load a resolvePathInContainer policy pay no periodic work.
var ricResyncOnce sync.Once

func startRICResyncLoop() {
	ricResyncOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(ricResyncInterval)
			defer ticker.Stop()
			for range ticker.C {
				resyncAllPolicies()
			}
		}()
	})
}

func currentInformerPods() ([]*corev1.Pod, bool) {
	ricPods.RLock()
	lister := ricPods.lister
	ricPods.RUnlock()
	if lister == nil {
		return nil, false
	}
	return lister.ListPods(), true
}

// policyKey is the registry key for a policy, qualified by namespace and domain
// so it matches the sensor manager's collection identity: policies sharing a
// name across namespaces or domains (e.g. k8s vs static) must not collide.
func policyKey(namespace, name, domain string) string {
	return domain + "/" + namespace + "/" + name
}

// selectorMatcher builds a podMatcher from the policy namespace and pod
// selector, mirroring policyfilter: a namespaced policy matches only its own
// namespace, a nil selector matches all pods in scope.
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

// registerResolvePathInContainer builds a fresh reconciler and attacher (a
// re-enabled policy starts clean) and returns the PostLoad/PreUnload hooks.
// The snapshot runs on its own goroutine: PostLoadHook holds the manager load
// lock and attaching re-enters the manager.
func registerResolvePathInContainer(spec *v1alpha1.TracingPolicySpec, polInfo *policyInfo) (postLoad, preUnload sensors.SensorHook) {
	// Uprobes and targets stay index-aligned; the reconciler attaches each
	// policy spec/inode pair independently so containers can share it.
	var uprobes []*v1alpha1.UProbeSpec
	var targets []string
	for i := range spec.UProbes {
		if spec.UProbes[i].ResolvePathInContainer {
			uprobes = append(uprobes, &spec.UProbes[i])
			targets = append(targets, spec.UProbes[i].Path)
		}
	}

	key := policyKey(polInfo.namespace, polInfo.name, polInfo.domain)
	match := selectorMatcher(polInfo.namespace, spec.PodSelector)
	var lifecycleMu sync.Mutex
	active := false
	var activeRec *containerUprobeReconciler

	postLoad = func() error {
		// Without CRI only new containers (via runtime hooks) can attach; warn
		// once per load so a silently-empty attach is diagnosable.
		if !option.Config.EnableCRI {
			logger.GetLogger().Warn("uprobe resolvePathInContainer: CRI is disabled; "+
				"only new containers (via runtime hooks) will be traced. "+
				"Containers already running when the policy loads are discovered "+
				"and resolved via CRI — enable --enable-cri to cover them.",
				"policy", key)
		}
		mgr := observer.GetSensorManager()
		gen := ricGeneration.Add(1)
		build := containerUprobeSensorBuilder(polInfo, spec, uprobes)
		att := newContainerSensorAttacher(key, gen, mgr, build)
		rec := newContainerUprobeReconciler(option.Config.ProcFS, targets, att, resolveContainerRootDir)
		ricRegistry.register(key, rec, match)
		startRICResyncLoop()
		lifecycleMu.Lock()
		active = true
		activeRec = rec
		lifecycleMu.Unlock()
		// Snapshot off the load lock, through the captured reconciler so a
		// late snapshot cannot attach into a newer policy generation.
		go snapshotExistingContainers(key, rec, match)
		return nil
	}
	preUnload = func() error {
		lifecycleMu.Lock()
		if !active {
			lifecycleMu.Unlock()
			return nil
		}
		active = false
		rec := activeRec
		lifecycleMu.Unlock()
		ricRegistry.unregister(key, rec)
		return nil
	}
	return postLoad, preUnload
}

// snapshotExistingContainers drives discovered containers matching the policy
// through the reconciler, keyed as (podUID/containerID) so a later pod delete
// detaches them.
func snapshotExistingContainers(key string, rec *containerUprobeReconciler, match podMatcher) {
	snapshot := newReconcilerSnapshot(rec, match)
	pods, all, available := existingContainerSnapshot()
	if !available {
		return
	}
	matched, applied := reconcileExistingContainers(snapshot, pods, all)
	// Log so a silently-empty snapshot is diagnosable.
	logger.GetLogger().Info("uprobe resolvePathInContainer: snapshot of existing containers",
		"policy", key, "running-containers", len(all), "informer-pods", len(pods), "matched", matched, "applied", applied)
}

// existingContainerSnapshot combines the informer cache with the available
// runtime source. CRI failures are not authoritative and must not prune;
// hooks-only mode derives running containers from informer statuses. The
// lister is registered at startup, before any policy can load.
func existingContainerSnapshot() ([]*corev1.Pod, []cri.RunningContainer, bool) {
	if option.Config.EnableCRI {
		running, available := discoverExistingContainers()
		if !available {
			return nil, nil, false
		}
		pods, available := currentInformerPods()
		return pods, running, available
	}
	pods, available := currentInformerPods()
	if !available {
		return nil, nil, false
	}
	return pods, informerRunningContainers(pods), true
}

func informerRunningContainers(pods []*corev1.Pod) []cri.RunningContainer {
	var running []cri.RunningContainer
	for _, pod := range pods {
		if pod == nil || pod.UID == "" {
			continue
		}
		for _, id := range podhelpers.PodContainersIDs(pod) {
			if id != "" {
				running = append(running, cri.RunningContainer{ID: id, PodUID: string(pod.UID)})
			}
		}
	}
	return running
}

type currentPod struct {
	namespace  string
	labels     map[string]string
	containers []string
}

func currentPodsByUID(pods []*corev1.Pod) map[string]currentPod {
	current := make(map[string]currentPod, len(pods))
	for _, pod := range pods {
		if pod == nil || pod.UID == "" {
			continue
		}
		current[string(pod.UID)] = currentPod{
			namespace:  pod.Namespace,
			labels:     pod.Labels,
			containers: podhelpers.PodContainersIDs(pod),
		}
	}
	return current
}

// reconcileExistingContainers applies one successful runtime/informer snapshot
// as exact desired sets. Tokens were reserved before collection, so pod events
// and later-started snapshots invalidate stale applications. Namespace and
// labels come from the informer: CRI sandbox labels may be stale.
func reconcileExistingContainers(snapshot reconcilerSnapshot, pods []*corev1.Pod, running []cri.RunningContainer) (matched, applied int) {
	current := currentPodsByUID(pods)
	desired := make(map[*containerUprobeReconciler]map[string]struct{}, len(snapshot))
	for _, entry := range snapshot {
		desired[entry.r] = make(map[string]struct{})
	}
	for _, container := range running {
		pod, ok := current[container.PodUID]
		if !ok {
			continue
		}
		if !slices.Contains(pod.containers, container.ID) {
			continue
		}
		for _, entry := range snapshot {
			if entry.match(pod.namespace, pod.labels) {
				desired[entry.r][containerKey(container.PodUID, container.ID)] = struct{}{}
			}
		}
	}
	for _, entry := range snapshot {
		keys := desired[entry.r]
		matched += len(keys)
		if entry.r.reconcileContainers(entry.token, keys) {
			applied++
		}
	}
	return matched, applied
}

// resyncAllPolicies reconciles runtime discovery against the current informer
// cache; failed CRI snapshots preserve existing attachments.
func resyncAllPolicies() {
	snapshot := ricRegistry.beginSnapshot()
	if len(snapshot) == 0 {
		return
	}
	pods, running, available := existingContainerSnapshot()
	if !available {
		return
	}
	reconcileExistingContainers(snapshot, pods, running)
}
