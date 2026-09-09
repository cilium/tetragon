// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows && !nok8s

package tracing

import (
	"maps"
	"slices"

	v1 "k8s.io/api/core/v1"

	"github.com/cilium/tetragon/pkg/manager/events"
	"github.com/cilium/tetragon/pkg/podhelpers"
)

// uprobePodHandlers routes pod events to the registry's matching reconcilers.
type uprobePodHandlers struct {
	reg *uprobeReconcilerRegistry
}

func newUprobePodHandlers(reg *uprobeReconcilerRegistry) *uprobePodHandlers {
	return &uprobePodHandlers{reg: reg}
}

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
	h.addKeys(recs, podContainerKeys(pod))
}

func (h *uprobePodHandlers) addKeys(recs []*containerUprobeReconciler, keys []string) {
	for _, key := range keys {
		for _, r := range recs {
			r.onContainerAdd(key)
		}
	}
}

func (h *uprobePodHandlers) onUpdate(oldPod, newPod *v1.Pod) {
	// Detach containers no longer running, or whose pod was relabeled out of a
	// matching selector, then attach the new state.
	newRecs := h.reg.matchingReconcilers(newPod.Namespace, newPod.Labels)
	// Most updates only carry status, so re-matching the old labels would
	// repeat the selector walk for the same answer.
	oldRecs := newRecs
	if oldPod.Namespace != newPod.Namespace || !maps.Equal(oldPod.Labels, newPod.Labels) {
		oldRecs = h.reg.matchingReconcilers(oldPod.Namespace, oldPod.Labels)
	}
	if len(newRecs) == 0 && len(oldRecs) == 0 {
		return
	}

	newKeys := podContainerKeys(newPod)
	for _, r := range oldRecs {
		stillMatches := slices.Contains(newRecs, r)
		for _, k := range podContainerKeys(oldPod) {
			if !stillMatches || !slices.Contains(newKeys, k) {
				r.onContainerDel(k)
			}
		}
	}
	h.addKeys(newRecs, newKeys)
}

func (h *uprobePodHandlers) onDelete(pod *v1.Pod) {
	// Delete events usually carry Terminated statuses, which
	// podContainerKeys would miss, so detach by pod instead.
	uid := string(pod.UID)
	for _, r := range h.reg.allReconcilers() {
		r.onPodDel(uid)
	}
}

// podContainerKeys returns the attach keys of pod's running containers.
func podContainerKeys(pod *v1.Pod) []string {
	uid := string(pod.UID)
	cids := podhelpers.PodContainersIDs(pod)
	keys := make([]string, 0, len(cids))
	for _, cid := range cids {
		if cid != "" {
			keys = append(keys, containerKey(uid, cid))
		}
	}
	return keys
}
