// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows && !nok8s

package tracing

import (
	"testing"

	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"

	"github.com/cilium/tetragon/pkg/cri"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	slimv1 "github.com/cilium/tetragon/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors"
)

// policyKey must be qualified by domain and namespace so it matches the sensor
// manager's collection identity: policies sharing a name across domains or
// namespaces must map to distinct registry keys, otherwise one policy's
// register would detach the other's reconciler.
func TestPolicyKeyDistinguishesDomainAndNamespace(t *testing.T) {
	keys := map[string]struct{}{}
	for _, k := range []string{
		policyKey("", "foo", "k8s"),
		policyKey("", "foo", "static"),
		policyKey("ns1", "foo", "k8s"),
		policyKey("ns2", "foo", "k8s"),
	} {
		keys[k] = struct{}{}
	}
	require.Len(t, keys, 4, "same name across domains/namespaces must not collide")
}

// selectorMatcher for a namespaced policy (policyNamespace != "") only matches
// pods in that namespace, mirroring policyfilter — a label-only selector must
// not attach across namespaces. A cluster-wide policy ("") matches any namespace.
func TestSelectorMatcherNamespaceScoping(t *testing.T) {
	sel := &slimv1.LabelSelector{MatchLabels: map[string]string{"app": "sshd"}}
	lbls := map[string]string{"app": "sshd"}

	nsScoped := selectorMatcher("prod", sel)
	require.True(t, nsScoped("prod", lbls), "must match its own namespace")
	require.False(t, nsScoped("dev", lbls), "must not match another namespace")

	clusterWide := selectorMatcher("", sel)
	require.True(t, clusterWide("prod", lbls))
	require.True(t, clusterWide("dev", lbls))

	// a nil selector matches all pods in scope, but a namespaced policy still
	// confines to its namespace.
	nsAll := selectorMatcher("prod", nil)
	require.True(t, nsAll("prod", nil))
	require.False(t, nsAll("dev", nil))
}

func TestResolvePathInContainerUsesPreDisableWithPreUnloadFallback(t *testing.T) {
	spec := &v1alpha1.TracingPolicySpec{
		UProbes: []v1alpha1.UProbeSpec{{
			Path:                   "/usr/bin/app",
			Symbols:                []string{"main"},
			ResolvePathInContainer: true,
		}},
	}
	polInfo, err := newPolicyInfoFromSpec("ns", "lifecycle", policyfilter.PolicyID(8), spec, nil)
	require.NoError(t, err)
	parent := &sensors.Sensor{Name: "generic_uprobe", Policy: polInfo.name, Namespace: polInfo.namespace}

	setupResolvePathInContainer(parent, spec, polInfo)

	require.NotNil(t, parent.PostMapLoadHook,
		"policy map initialization must be a fatal load phase")
	require.NotNil(t, parent.PreDisableHook,
		"disable must tear children down before waiting for the manager load lock")
	require.NotNil(t, parent.PreUnloadHook,
		"delete and load-error teardown still need an unload fallback")
	require.Nil(t, parent.PostUnloadHook,
		"child cleanup must complete before parent policy maps are unloaded")
}

// CRI sandbox labels are fixed at sandbox creation. Resync must use the
// informer's current labels so a relabeled pod cannot be revived by stale CRI
// metadata after its live update detached it.
func TestReconcileExistingContainersUsesCurrentPodLabels(t *testing.T) {
	reg := newUprobeReconcilerRegistry()
	att := newFakeAttacher()
	match := func(ns string, lbls map[string]string) bool { return ns == "ns" && lbls["app"] == "sshd" }
	reg.register("policyA", newContainerUprobeReconciler("/procRoot", []string{"/lib/a.so"}, att, fakeResolveRoot()), match)
	h := newUprobePodHandlers(reg)

	oldPod := labeledPod("uid-1", "ns", map[string]string{"app": "sshd"}, "abc")
	h.onAdd(oldPod)
	require.Equal(t, []string{"uid-1/abc"}, att.attachedKeys())

	currentPod := labeledPod("uid-1", "ns", map[string]string{"app": "nginx"}, "abc")
	h.onUpdate(oldPod, currentPod)
	require.Empty(t, att.attachedKeys())

	// RunningContainer intentionally carries no CRI namespace/labels, so a
	// relabeled pod cannot be revived by stale sandbox metadata.
	reconcileExistingContainers(reg.beginSnapshot(), []*v1.Pod{currentPod}, []cri.RunningContainer{{
		ID:     "abc",
		PodUID: "uid-1",
	}})
	require.Empty(t, att.attachedKeys(), "informer labels no longer select the pod, it must stay detached")

	selectedPod := labeledPod("uid-2", "ns", map[string]string{"app": "sshd"}, "def")
	reconcileExistingContainers(reg.beginSnapshot(), []*v1.Pod{currentPod, selectedPod}, []cri.RunningContainer{
		{ID: "abc", PodUID: "uid-1"},
		{ID: "def", PodUID: "uid-2"},
	})
	require.Equal(t, []string{"uid-2/def"}, att.attachedKeys(),
		"current informer labels must select a pod even when CRI labels do not")
}

func TestStaleContainerSnapshotCannotReviveRelabeledPod(t *testing.T) {
	reg := newUprobeReconcilerRegistry()
	att := newFakeAttacher()
	match := func(_ string, labels map[string]string) bool { return labels["app"] == "sshd" }
	rec := newContainerUprobeReconciler("/procRoot", []string{"/lib/a.so"}, att, fakeResolveRoot())
	reg.register("policyA", rec, match)
	h := newUprobePodHandlers(reg)

	selected := labeledPod("uid-1", "ns", map[string]string{"app": "sshd"}, "abc")
	unselected := labeledPod("uid-1", "ns", map[string]string{"app": "nginx"}, "abc")
	h.onAdd(selected)

	// A resync computed this desired set before the informer delivered the
	// newer labels, but has not applied it yet.
	token := rec.beginSnapshot()
	desired := map[string]struct{}{"uid-1/abc": {}}

	h.onUpdate(selected, unselected)
	require.Empty(t, att.attachedKeys())
	require.False(t, rec.reconcileContainers(token, desired), "the pod update must invalidate the older snapshot")

	require.Empty(t, att.attachedKeys(), "a stale snapshot must not revive a pod after its update detached it")
}

// A successful resync is an exact reconciliation. Pods absent from the
// informer and containers absent from CRI must be detached even if their delete
// event was missed.
func TestReconcileExistingContainersPrunesStaleKeys(t *testing.T) {
	reg := newUprobeReconcilerRegistry()
	att := newFakeAttacher()
	reg.register("policyA", newContainerUprobeReconciler("/procRoot", []string{"/lib/a.so"}, att, fakeResolveRoot()), matchAllPods)
	h := newUprobePodHandlers(reg)

	pod1 := runningPod("uid-1", "abc")
	pod2 := runningPod("uid-2", "def")
	h.onAdd(pod1)
	h.onAdd(pod2)
	require.ElementsMatch(t, []string{"uid-1/abc", "uid-2/def"}, att.attachedKeys())

	// uid-2 was force-deleted from Kubernetes, but CRI still reports its
	// sandbox and container.
	reconcileExistingContainers(reg.beginSnapshot(), []*v1.Pod{pod1}, []cri.RunningContainer{
		{ID: "abc", PodUID: "uid-1"},
		{ID: "def", PodUID: "uid-2"},
	})
	require.Equal(t, []string{"uid-1/abc"}, att.attachedKeys())

	// CRI has now removed uid-1's container; the add-only implementation left
	// this key attached forever.
	reconcileExistingContainers(reg.beginSnapshot(), []*v1.Pod{pod1}, nil)
	require.Empty(t, att.attachedKeys())
}

func TestLaterContainerSnapshotInvalidatesEarlierSnapshot(t *testing.T) {
	reg := newUprobeReconcilerRegistry()
	att := newFakeAttacher()
	rec := newContainerUprobeReconciler("/procRoot", []string{"/lib/a.so"}, att, fakeResolveRoot())
	reg.register("policyA", rec, matchAllPods)

	pod := runningPod("uid-1", "abc")
	rec.onContainerAdd("uid-1/abc")
	older := newReconcilerSnapshot(rec, matchAllPods) // initial policy snapshot
	olderPods := []*v1.Pod{pod}
	olderRunning := []cri.RunningContainer{{ID: "abc", PodUID: "uid-1"}}

	// This later-started snapshot completes first and observes that the
	// container has disappeared from CRI.
	newer := reg.beginSnapshot() // periodic all-policy snapshot
	_, applied := reconcileExistingContainers(newer, []*v1.Pod{pod}, nil)
	require.Equal(t, 1, applied)
	require.Empty(t, att.attachedKeys())

	_, applied = reconcileExistingContainers(older, olderPods, olderRunning)
	require.Zero(t, applied, "an earlier snapshot finishing later must be rejected")
	require.Empty(t, att.attachedKeys())
}

func TestInformerRunningContainersForHooksOnlyResync(t *testing.T) {
	pod := runningPod("uid-1", "abc")
	pod.Status.ContainerStatuses = append(pod.Status.ContainerStatuses, v1.ContainerStatus{
		ContainerID: "containerd://stopped",
		State:       v1.ContainerState{Terminated: &v1.ContainerStateTerminated{}},
	})

	require.Equal(t, []cri.RunningContainer{{ID: "abc", PodUID: "uid-1"}}, informerRunningContainers([]*v1.Pod{pod}),
		"hooks-only resync must retry current running containers without reviving stopped ones")
}
