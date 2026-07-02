// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import "sync"

// uprobeReconcilerRegistry holds the per-policy containerUprobeReconcilers for
// resolvePathInContainer uprobe policies, and routes pod/container lifecycle
// events to the right reconciler.
//
// It is the single subscriber to pod events (wired onto the shared pod
// informer, so no second informer is created): the pod-event handler asks for
// the reconcilers whose policies match a pod (matchingReconcilers) and drives
// them directly. Pods matching no registered policy route nowhere.

// podMatcher reports whether a pod (by namespace and labels) is selected by a
// policy. It is set when a policy is registered so the pod-event handler can
// determine which policies a pod matches.
type podMatcher func(namespace string, labels map[string]string) bool

type registeredReconciler struct {
	r     *containerUprobeReconciler
	match podMatcher
}

type uprobeReconcilerRegistry struct {
	mu          sync.RWMutex
	reconcilers map[string]*registeredReconciler // policy long-name -> reconciler
}

func newUprobeReconcilerRegistry() *uprobeReconcilerRegistry {
	return &uprobeReconcilerRegistry{
		reconcilers: map[string]*registeredReconciler{},
	}
}

// register associates a reconciler with a policy. Called when a
// resolvePathInContainer uprobe policy is loaded. match must be non-nil (see
// selectorMatcher, which returns a match-all matcher for a nil selector).
func (reg *uprobeReconcilerRegistry) register(policy string, r *containerUprobeReconciler, match podMatcher) {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	reg.reconcilers[policy] = &registeredReconciler{r: r, match: match}
}

// matchingReconcilers returns the reconcilers of the registered policies whose
// pod matcher selects the given pod. A reconciler handed out here may see calls
// after its policy is unregistered; those are no-ops once detachAll has marked
// it closed.
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

// unregister removes a policy's reconciler and detaches all of its containers.
// Called when the policy is removed.
func (reg *uprobeReconcilerRegistry) unregister(policy string) {
	reg.mu.Lock()
	rr := reg.reconcilers[policy]
	delete(reg.reconcilers, policy)
	reg.mu.Unlock()
	if rr != nil {
		rr.r.detachAll()
	}
}
