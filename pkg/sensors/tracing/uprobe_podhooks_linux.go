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

// containerKey returns the reconciler attach key for a container within a pod.
// Both inputs are "/"-free, so the separator is unambiguous.
func containerKey(podUID, containerID string) string {
	return podUID + "/" + containerID
}

// uprobePodHandlers translates pod add/update/delete events into calls on the
// registry's matching reconcilers.
type uprobePodHandlers struct {
	reg *uprobeReconcilerRegistry
}

func newUprobePodHandlers(reg *uprobeReconcilerRegistry) *uprobePodHandlers {
	return &uprobePodHandlers{reg: reg}
}

// register wires the handlers into the shared pod-event source; no new
// informer is created.
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
	invalidateReconcilerSnapshots(recs)
	h.add(pod, recs)
}

func (h *uprobePodHandlers) add(pod *v1.Pod, recs []*containerUprobeReconciler) {
	if len(recs) == 0 {
		return
	}
	h.addKeys(recs, h.containerKeys(pod))
}

func (h *uprobePodHandlers) addKeys(recs []*containerUprobeReconciler, keys []string) {
	for _, key := range keys {
		for _, r := range recs {
			r.onContainerAdd(key)
		}
	}
}

func (h *uprobePodHandlers) onUpdate(oldPod, newPod *v1.Pod) {
	// Detach containers that are no longer running or whose pod was relabeled
	// out of a previously matching policy's selector, then attach the new state.
	oldRecs := h.reg.matchingReconcilers(oldPod.Namespace, oldPod.Labels)
	newRecs := h.reg.matchingReconcilers(newPod.Namespace, newPod.Labels)
	if len(oldRecs) == 0 && len(newRecs) == 0 {
		return
	}
	invalidateReconcilerSnapshots(oldRecs)
	invalidateReconcilerSnapshots(newRecs)
	newContainerKeys := h.containerKeys(newPod)
	if len(oldRecs) > 0 {
		newKeys := make(map[string]struct{}, len(newContainerKeys))
		for _, k := range newContainerKeys {
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
	h.addKeys(newRecs, newContainerKeys)
}

func (h *uprobePodHandlers) onDelete(pod *v1.Pod) {
	// Delete events usually carry Terminated container statuses, which
	// containerKeys (Running-only) would miss; detach by pod-UID prefix instead.
	uid := string(pod.UID)
	recs := h.reg.allReconcilers()
	invalidateReconcilerSnapshots(recs)
	for _, r := range recs {
		r.onPodDel(uid)
	}
}

// invalidateReconcilerSnapshots marks a live informer event before its handler
// performs any slow per-container work. Invalidating a reconciler more than
// once is harmless: its version just advances again.
func invalidateReconcilerSnapshots(recs []*containerUprobeReconciler) {
	for _, rec := range recs {
		rec.invalidateSnapshots()
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
