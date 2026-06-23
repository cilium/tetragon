// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"sync"

	"github.com/cilium/tetragon/pkg/logger"
)

// podMatcher reports whether a pod (by namespace and labels) is selected by a
// policy.
type podMatcher func(namespace string, labels map[string]string) bool

type registeredReconciler struct {
	r     *containerUprobeReconciler
	match podMatcher
}

type reconcilerSnapshotEntry struct {
	r     *containerUprobeReconciler
	match podMatcher
	token reconcileSnapshotToken
}

type reconcilerSnapshot []reconcilerSnapshotEntry

// uprobeReconcilerRegistry holds the per-policy reconcilers and routes pod
// lifecycle events to them, wired once onto the shared pod informer.
type uprobeReconcilerRegistry struct {
	mu          sync.RWMutex
	reconcilers map[string]*registeredReconciler // policy long-name -> reconciler
}

func newUprobeReconcilerRegistry() *uprobeReconcilerRegistry {
	return &uprobeReconcilerRegistry{
		reconcilers: map[string]*registeredReconciler{},
	}
}

func newReconcilerSnapshot(r *containerUprobeReconciler, match podMatcher) reconcilerSnapshot {
	return reconcilerSnapshot{{r: r, match: match, token: r.beginSnapshot()}}
}

// beginSnapshot reserves per-policy versions before slow runtime/informer
// collection. A later pod event or snapshot start invalidates each token.
func (reg *uprobeReconcilerRegistry) beginSnapshot() reconcilerSnapshot {
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	out := make(reconcilerSnapshot, 0, len(reg.reconcilers))
	for _, rr := range reg.reconcilers {
		out = append(out, reconcilerSnapshotEntry{r: rr.r, match: rr.match, token: rr.r.beginSnapshot()})
	}
	return out
}

// register associates a reconciler with a loaded policy. match must be non-nil.
// The caller must unregister before re-registering a policy key; detach any
// stale entry defensively so a violated invariant leaks a warning, not BPF
// attachments.
func (reg *uprobeReconcilerRegistry) register(policy string, r *containerUprobeReconciler, match podMatcher) {
	reg.mu.Lock()
	old := reg.reconcilers[policy]
	reg.reconcilers[policy] = &registeredReconciler{r: r, match: match}
	reg.mu.Unlock()
	if old != nil && old.r != r {
		logger.GetLogger().Warn("uprobe reconciler registry: overwriting an active registration, detaching stale reconciler",
			"policy", policy)
		old.r.detachAll()
	}
}

// matchingReconcilers returns the reconcilers of the policies whose matcher
// selects the given pod. Calls on a reconciler after its policy is
// unregistered are no-ops.
func (reg *uprobeReconcilerRegistry) matchingReconcilers(namespace string, labels map[string]string) []*containerUprobeReconciler {
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	var out []*containerUprobeReconciler
	for _, rr := range reg.reconcilers {
		if rr.match(namespace, labels) {
			out = append(out, rr.r)
		}
	}
	return out
}

// allReconcilers returns the reconcilers of all registered policies.
func (reg *uprobeReconcilerRegistry) allReconcilers() []*containerUprobeReconciler {
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	out := make([]*containerUprobeReconciler, 0, len(reg.reconcilers))
	for _, rr := range reg.reconcilers {
		out = append(out, rr.r)
	}
	return out
}

// unregister detaches all of r's containers and removes the policy's registry
// entry only if r is still the registered reconciler, so a stale teardown
// racing a same-name re-registration cannot remove the newer entry.
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
