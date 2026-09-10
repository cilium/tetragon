// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"sync"

	"github.com/cilium/tetragon/pkg/logger"
)

// podMatcher reports whether a policy selects a pod.
type podMatcher func(namespace string, labels map[string]string) bool

type registeredReconciler struct {
	r     *containerUprobeReconciler
	match podMatcher
}

// uprobeReconcilerRegistry routes pod lifecycle events to the per-policy
// reconcilers.
type uprobeReconcilerRegistry struct {
	mu          sync.RWMutex
	reconcilers map[string]*registeredReconciler // policy long-name -> reconciler
}

func newUprobeReconcilerRegistry() *uprobeReconcilerRegistry {
	return &uprobeReconcilerRegistry{
		reconcilers: map[string]*registeredReconciler{},
	}
}

// register claims the routing slot for a loaded policy. A concurrent
// delete+re-add of the same key can leave a stale entry here; the stale
// reconciler is torn down by its own policy's unregister rather than inline,
// so register never waits on another policy's in-flight attach.
func (reg *uprobeReconcilerRegistry) register(policy string, r *containerUprobeReconciler, match podMatcher) {
	reg.mu.Lock()
	old := reg.reconcilers[policy]
	reg.reconcilers[policy] = &registeredReconciler{r: r, match: match}
	reg.mu.Unlock()
	if old != nil && old.r != r {
		logger.GetLogger().Warn("uprobe reconciler registry: overwriting an active registration; stale reconciler will be detached by its own unregister",
			"policy", policy)
	}
}

func (reg *uprobeReconcilerRegistry) matchingReconcilers(namespace string, labels map[string]string) []*containerUprobeReconciler {
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	out := make([]*containerUprobeReconciler, 0, len(reg.reconcilers))
	for _, rr := range reg.reconcilers {
		if rr.match(namespace, labels) {
			out = append(out, rr.r)
		}
	}
	return out
}

func (reg *uprobeReconcilerRegistry) allReconcilers() []*containerUprobeReconciler {
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	out := make([]*containerUprobeReconciler, 0, len(reg.reconcilers))
	for _, rr := range reg.reconcilers {
		out = append(out, rr.r)
	}
	return out
}

// unregister detaches all of r's containers, and drops the registry entry only
// if r is still the registered reconciler, so a stale teardown racing a
// re-registration cannot remove the newer entry.
func (reg *uprobeReconcilerRegistry) unregister(policy string, r *containerUprobeReconciler) {
	if r == nil {
		return
	}
	reg.mu.Lock()
	if rr := reg.reconcilers[policy]; rr != nil && rr.r == r {
		delete(reg.reconcilers, policy)
	}
	reg.mu.Unlock()
	r.detachAll()
}
