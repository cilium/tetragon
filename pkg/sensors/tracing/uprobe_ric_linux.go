// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows && !nok8s

package tracing

import (
	"errors"
	"maps"
	"sync"
	"sync/atomic"

	corev1 "k8s.io/api/core/v1"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	slimv1 "github.com/cilium/tetragon/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/tetragon/pkg/labels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/manager/events"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors"
)

var ricRegistry = newUprobeReconcilerRegistry()

var (
	errRICNoPodLister   = errors.New("no pod lister supplied for informer snapshots")
	errRICNoPodHandlers = errors.New("resolvePathInContainer requires the in-cluster pod informer, which this agent configuration does not provide")
)

// ricPods exposes the informer cache to the initial attach. A func rather than
// pkg/manager's type keeps controller-runtime out of this package.
var ricPods struct {
	sync.RWMutex
	listPods func() ([]*corev1.Pod, error)
}

var ricGeneration atomic.Uint64

// setupResolvePathInContainer wires the per-container reconciler onto sensor:
// the parent owns the policy maps before PostLoad attaches containers, and
// PreUnload removes the children while those maps are still pinned.
func setupResolvePathInContainer(sensor *sensors.Sensor, spec *v1alpha1.TracingPolicySpec, polInfo *policyInfo) {
	uprobe := resolvePathInContainerSpec(spec)
	if uprobe == nil {
		return
	}
	prepareResolvePathInContainerPolicyMaps(sensor, polInfo)
	postLoad, preUnload := registerResolvePathInContainer(sensor, uprobe, spec, polInfo)
	// The caller set a PostLoadHook on this sensor already; keep both.
	closeFiles := sensor.PostLoadHook
	sensor.PostLoadHook = func() error { return errors.Join(closeFiles(), postLoad()) }
	sensor.PreUnloadHook = preUnload
}

// RegisterResolvePathInContainerPodHandlers wires the pod-event handlers into
// src and retains listPods for the initial attach. Called once at startup.
func RegisterResolvePathInContainerPodHandlers(src events.PodEventSource, listPods func() ([]*corev1.Pod, error)) error {
	if listPods == nil {
		return errRICNoPodLister
	}
	if err := newUprobePodHandlers(ricRegistry).register(src); err != nil {
		return err
	}
	ricPods.Lock()
	ricPods.listPods = listPods
	ricPods.Unlock()
	return nil
}

func informerPods() func() ([]*corev1.Pod, error) {
	ricPods.RLock()
	defer ricPods.RUnlock()
	return ricPods.listPods
}

// checkResolvePathInContainerSupport rejects a configuration that would never
// deliver pod events, such as an out-of-cluster kubeconfig.
func checkResolvePathInContainerSupport() error {
	if informerPods() == nil {
		return errRICNoPodHandlers
	}
	return nil
}

// policyKey carries the same triple as the sensor manager's collection
// identity, so policies sharing a name across namespaces or domains (e.g. k8s
// vs static) cannot collide.
func policyKey(namespace, name, domain string) string {
	return domain + "/" + namespace + "/" + name
}

// selectorMatcher mirrors policyfilter: a namespaced policy matches only its
// own namespace, a nil selector matches all pods in scope.
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

// registerResolvePathInContainer returns the PostLoad/PreUnload hooks. Each
// load builds a fresh reconciler and attacher, so a re-enabled policy starts
// clean.
func registerResolvePathInContainer(parent *sensors.Sensor, uprobe *v1alpha1.UProbeSpec, spec *v1alpha1.TracingPolicySpec, polInfo *policyInfo) (postLoad, preUnload sensors.SensorHook) {
	key := policyKey(polInfo.namespace, polInfo.name, polInfo.domain)
	match := selectorMatcher(polInfo.namespace, spec.PodSelector)
	var activeRec atomic.Pointer[containerUprobeReconciler]

	postLoad = func() error {
		procFS := option.Config.ProcFS
		gen := ricGeneration.Add(1)
		att := newContainerSensorAttacher(key, gen, parent.BpfDir,
			containerUprobeSensorBuilder(polInfo, spec, uprobe))
		rec := newContainerUprobeReconciler(procFS, uprobe.Path, att,
			func(containerID string) string { return resolveContainerRootDir(containerID, procFS) })
		ricRegistry.register(key, rec, match)
		activeRec.Store(rec)

		// Claim the running containers now, but attach them off the manager's
		// load lock, which this hook holds.
		keys := runningContainerKeys(match)
		rec.markWanted(keys...)
		logger.GetLogger().Info("uprobe resolvePathInContainer: attaching containers running at policy load",
			"policy", key, "containers", len(keys))
		go func() {
			for _, k := range keys {
				rec.attachWanted(k)
			}
		}()
		return nil
	}
	preUnload = func() error {
		rec := activeRec.Swap(nil)
		if rec == nil {
			return nil
		}
		ricRegistry.unregister(key, rec)
		return nil
	}
	return postLoad, preUnload
}

// runningContainerKeys returns the attach keys of the running containers of
// every pod the policy selects.
func runningContainerKeys(match podMatcher) []string {
	listPods := informerPods()
	if listPods == nil {
		return nil
	}
	pods, err := listPods()
	if err != nil {
		logger.GetLogger().Warn("uprobe resolvePathInContainer: failed to list pods; "+
			"only containers starting from now will be traced", logfields.Error, err)
		return nil
	}
	var keys []string
	for _, pod := range pods {
		if pod == nil || pod.UID == "" || !match(pod.Namespace, pod.Labels) {
			continue
		}
		keys = append(keys, podContainerKeys(pod)...)
	}
	return keys
}
