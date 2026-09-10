// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// matchAllPods is a podMatcher that selects every pod, standing in for a policy
// whose selector matches everything.
func matchAllPods(string, map[string]string) bool { return true }

// the registry routes container add/del events to the reconcilers of the
// policies whose matcher selects the pod, and to nothing when no policy matches.
func TestReconcilerRegistryRouting(t *testing.T) {
	reg := newUprobeReconcilerRegistry()

	attA := newFakeAttacher()
	rA := newContainerUprobeReconciler("", "/lib/a.so", attA, newContainerRoots(t, "/lib/a.so").resolver())
	attB := newFakeAttacher()
	rB := newContainerUprobeReconciler("", "/lib/b.so", attB, newContainerRoots(t, "/lib/b.so").resolver())

	matchNS := func(ns string) podMatcher {
		return func(namespace string, _ map[string]string) bool { return namespace == ns }
	}
	reg.register("policyA", rA, matchNS("nsA"))
	reg.register("policyB", rB, matchNS("nsB"))

	for _, r := range reg.matchingReconcilers("nsA", nil) {
		r.onContainerAdd("pod1/c1")
	}
	for _, r := range reg.matchingReconcilers("nsB", nil) {
		r.onContainerAdd("pod2/c2")
	}
	// a pod matching no policy routes nowhere.
	require.Empty(t, reg.matchingReconcilers("nsZ", nil))

	require.Equal(t, []string{"pod1/c1"}, attA.attachedKeys())
	require.Equal(t, []string{"pod2/c2"}, attB.attachedKeys())

	// deletes route to every registered reconciler; unknown keys are no-ops.
	for _, r := range reg.allReconcilers() {
		r.onContainerDel("pod1/c1")
	}
	require.Empty(t, attA.attachedKeys())
	require.Equal(t, []string{"pod2/c2"}, attB.attachedKeys())
}

// matchingReconcilers returns the reconcilers whose matcher selects
// the pod.
// noRoots resolves nothing, for tests that never attach.
var noRoots rootResolver = func(string) string { return "" }

func TestReconcilerRegistryMatchingReconcilers(t *testing.T) {
	reg := newUprobeReconcilerRegistry()
	att := newFakeAttacher()

	rAll := newContainerUprobeReconciler("", "/a", att, noRoots)
	rSshd := newContainerUprobeReconciler("", "/b", att, noRoots)

	reg.register("policyAll", rAll, matchAllPods)
	// policySshd: matches only namespace "prod" with label app=sshd.
	reg.register("policySshd", rSshd, func(ns string, lbls map[string]string) bool {
		return ns == "prod" && lbls["app"] == "sshd"
	})

	require.ElementsMatch(t, []*containerUprobeReconciler{rAll, rSshd},
		reg.matchingReconcilers("prod", map[string]string{"app": "sshd"}))
	require.ElementsMatch(t, []*containerUprobeReconciler{rAll},
		reg.matchingReconcilers("dev", map[string]string{"app": "sshd"}))
	require.ElementsMatch(t, []*containerUprobeReconciler{rAll},
		reg.matchingReconcilers("prod", map[string]string{"app": "nginx"}))
}

// unregistering a policy detaches all of its containers and stops routing.
func TestReconcilerRegistryUnregisterDetachesAll(t *testing.T) {
	reg := newUprobeReconcilerRegistry()
	att := newFakeAttacher()
	r := newContainerUprobeReconciler("", "/lib/a.so", att, newContainerRoots(t, "/lib/a.so").resolver())

	reg.register("policyA", r, matchAllPods)
	r.onContainerAdd("pod1/c1")
	r.onContainerAdd("pod1/c2")
	require.Len(t, att.attachedKeys(), 2)

	reg.unregister("policyA", r)
	// unregister calls detachAll synchronously, so every container is detached
	// by the time it returns.
	require.Empty(t, att.attachedKeys(), "unregister must detach all containers")

	// the unregistered policy no longer matches, and a late add on its (closed)
	// reconciler is a no-op.
	require.Empty(t, reg.matchingReconcilers("any", nil))
	r.onContainerAdd("pod1/c3")
	require.Empty(t, att.attachedKeys())
}

// A stale teardown racing a same-name re-registration must detach only its own
// reconciler, leaving the newer registration in place.
func TestReconcilerRegistryStaleUnregisterKeepsNewer(t *testing.T) {
	reg := newUprobeReconcilerRegistry()
	attOld := newFakeAttacher()
	rOld := newContainerUprobeReconciler("", "/lib/a.so", attOld, newContainerRoots(t, "/lib/a.so").resolver())
	attNew := newFakeAttacher()
	rNew := newContainerUprobeReconciler("", "/lib/a.so", attNew, newContainerRoots(t, "/lib/a.so").resolver())

	reg.register("policyA", rOld, matchAllPods)
	rOld.onContainerAdd("pod1/c1")
	// Same-name re-registration claims the routing slot but must NOT detach the
	// stale reconciler inline, which would make a policy load wait on another
	// policy's in-flight attach; it is torn down by its own unregister.
	reg.register("policyA", rNew, matchAllPods)
	require.Equal(t, []string{"pod1/c1"}, attOld.attachedKeys(),
		"overwrite must not detach the stale reconciler inline")
	require.ElementsMatch(t, []*containerUprobeReconciler{rNew},
		reg.matchingReconcilers("any", nil), "new reconciler owns the routing slot")
	rNew.onContainerAdd("pod1/c1")

	// The stale reconciler's own (late) unregister detaches it without removing
	// the newer registration.
	reg.unregister("policyA", rOld)
	require.Empty(t, attOld.attachedKeys(), "stale reconciler detached by its unregister")
	require.ElementsMatch(t, []*containerUprobeReconciler{rNew},
		reg.matchingReconcilers("any", nil))
	require.Equal(t, []string{"pod1/c1"}, attNew.attachedKeys())

	reg.unregister("policyA", rNew)
	require.Empty(t, attNew.attachedKeys())
	require.Empty(t, reg.matchingReconcilers("any", nil))
}
