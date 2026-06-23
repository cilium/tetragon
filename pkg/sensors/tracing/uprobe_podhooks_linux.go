// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows && !nok8s

package tracing

import (
	"slices"

	v1 "k8s.io/api/core/v1"

	"github.com/cilium/tetragon/pkg/manager/events"
	"github.com/cilium/tetragon/pkg/podhelpers"
)

// containerKey returns a stable identifier for a container within a pod, used
// as the reconciler attach key. It combines the pod UID with the container id
// so the same key can be reconstructed on add and delete. Both inputs are
// "/"-free (pod UIDs are UUIDs, container ids are runtime-prefix-stripped hex),
// so the separator is unambiguous.
func containerKey(podUID, containerID string) string {
	return podUID + "/" + containerID
}

// uprobePodHandlers translates pod add/update/delete events into reconciler
// calls. Container->policy matching goes through the registry's pod matchers
// (the same selector machinery as policyfilter); adds route every container in
// a matching pod to the matching policies' reconcilers, deletes route to every
// registered reconciler (unknown keys are no-ops). Per-container root
// resolution (runtime hook / CRI) happens later in the reconciler, keyed by
// container id.
//
// The cache.DeletedFinalStateUnknown unwrap and the *v1.Pod type assertion
// happen in the pod-event adapter (see pkg/manager), so these callbacks deal
// only with concrete *v1.Pod values.
type uprobePodHandlers struct {
	reg *uprobeReconcilerRegistry
}

func newUprobePodHandlers(reg *uprobeReconcilerRegistry) *uprobePodHandlers {
	return &uprobePodHandlers{reg: reg}
}

// register wires the handlers into the supplied pod-event source. It registers
// no new informer of its own — the source is the shared pod informer, the same
// one policyfilter attaches to.
func (h *uprobePodHandlers) register(src events.PodEventSource) error {
	if err := src.OnPodAdd(h.onAdd); err != nil {
		return err
	}
	if err := src.OnPodUpdate(h.onUpdate); err != nil {
		return err
	}
	return src.OnPodDelete(h.onDelete)
}

func (h *uprobePodHandlers) onAdd(pod *v1.Pod) {
	recs := h.reg.matchingReconcilers(pod.Namespace, pod.Labels)
	if len(recs) == 0 {
		return
	}
	for _, key := range h.containerKeys(pod) {
		for _, r := range recs {
			r.onContainerAdd(key)
		}
	}
}

func (h *uprobePodHandlers) onUpdate(oldPod, newPod *v1.Pod) {
	// A pod update must detach a container's child sensor when either
	//  (a) the container is no longer running (terminated/removed without the
	//      pod being deleted), or
	//  (b) the pod's labels changed so it no longer matches a policy that
	//      previously selected it.
	// Without (b) a pod relabeled out of a policy's podSelector would keep its
	// uprobe attached until the pod is finally deleted. Detach before onAdd
	// re-attaches the policies that match the new labels.
	oldRecs := h.reg.matchingReconcilers(oldPod.Namespace, oldPod.Labels)
	if len(oldRecs) > 0 {
		newRecs := h.reg.matchingReconcilers(newPod.Namespace, newPod.Labels)
		newKeys := make(map[string]struct{})
		for _, k := range h.containerKeys(newPod) {
			newKeys[k] = struct{}{}
		}
		oldKeys := h.containerKeys(oldPod)
		for _, r := range oldRecs {
			stillMatches := slices.Contains(newRecs, r)
			for _, k := range oldKeys {
				if _, present := newKeys[k]; !present || !stillMatches {
					r.onContainerDel(k)
				}
			}
		}
	}
	h.onAdd(newPod)
}

func (h *uprobePodHandlers) onDelete(pod *v1.Pod) {
	h.detachKeys(h.containerKeys(pod))
}

// detachKeys routes a detach for each key to every registered reconciler;
// unknown keys are no-ops in each reconciler.
func (h *uprobePodHandlers) detachKeys(keys []string) {
	recs := h.reg.allReconcilers()
	for _, key := range keys {
		for _, r := range recs {
			r.onContainerDel(key)
		}
	}
}

func (h *uprobePodHandlers) containerKeys(pod *v1.Pod) []string {
	uid := string(pod.UID)
	cids := podhelpers.PodContainersIDs(pod)
	keys := make([]string, 0, len(cids))
	for _, cid := range cids {
		keys = append(keys, containerKey(uid, cid))
	}
	return keys
}
