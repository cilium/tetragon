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

// T5: the registry routes container add/del events to the reconcilers of the
// policies whose matcher selects the pod, and to nothing when no policy matches.
func TestReconcilerRegistryRouting(t *testing.T) {
	reg := newUprobeReconcilerRegistry()

	attA := newFakeAttacher()
	rA := newContainerUprobeReconciler("/procRoot", []string{"/lib/a.so"}, attA, fakeResolveRoot())
	attB := newFakeAttacher()
	rB := newContainerUprobeReconciler("/procRoot", []string{"/lib/b.so"}, attB, fakeResolveRoot())

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

// Wiring-3: matchingReconcilers returns the reconcilers whose matcher selects
// the pod.
func TestReconcilerRegistryMatchingReconcilers(t *testing.T) {
	reg := newUprobeReconcilerRegistry()
	att := newFakeAttacher()

	rAll := newContainerUprobeReconciler("/p", []string{"/a"}, att, fakeResolveRoot())
	rSshd := newContainerUprobeReconciler("/p", []string{"/b"}, att, fakeResolveRoot())

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

// T6: registering a policy then snapshotting existing containers attaches them,
// and subsequent live events still route correctly. This mirrors the production
// path (register + snapshot of existing containers).
func TestReconcilerRegistrySnapshotOnRegister(t *testing.T) {
	reg := newUprobeReconcilerRegistry()
	att := newFakeAttacher()
	r := newContainerUprobeReconciler("/procRoot", []string{"/lib/a.so"}, att, fakeResolveRoot())

	reg.register("policyA", r, matchAllPods)
	for _, key := range []string{"pod1/c1", "pod1/c2"} {
		r.onContainerAdd(key)
	}

	require.ElementsMatch(t, []string{"pod1/c1", "pod1/c2"}, att.attachedKeys())

	// subsequent live events still route correctly after the snapshot.
	for _, rec := range reg.matchingReconcilers("any", nil) {
		rec.onContainerAdd("pod2/c3")
	}
	require.Len(t, att.attachedKeys(), 3)
}

// T5: unregistering a policy detaches all of its containers and stops routing.
func TestReconcilerRegistryUnregisterDetachesAll(t *testing.T) {
	reg := newUprobeReconcilerRegistry()
	att := newFakeAttacher()
	r := newContainerUprobeReconciler("/procRoot", []string{"/lib/a.so"}, att, fakeResolveRoot())

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
	rOld := newContainerUprobeReconciler("/procRoot", []string{"/lib/a.so"}, attOld, fakeResolveRoot())
	attNew := newFakeAttacher()
	rNew := newContainerUprobeReconciler("/procRoot", []string{"/lib/a.so"}, attNew, fakeResolveRoot())

	reg.register("policyA", rOld, matchAllPods)
	rOld.onContainerAdd("pod1/c1")
	// Same-name re-registration claims the routing slot but must NOT detach the
	// stale reconciler inline (that would deadlock under the manager load lock);
	// the stale reconciler is torn down by its own unregister.
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
