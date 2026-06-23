// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows && !nok8s

package tracing

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func runningPod(uid string, containerIDs ...string) *v1.Pod {
	return labeledPod(uid, "", nil, containerIDs...)
}

func labeledPod(uid, namespace string, podLabels map[string]string, containerIDs ...string) *v1.Pod {
	statuses := make([]v1.ContainerStatus, 0, len(containerIDs))
	for _, cid := range containerIDs {
		statuses = append(statuses, v1.ContainerStatus{
			ContainerID: "containerd://" + cid,
			State:       v1.ContainerState{Running: &v1.ContainerStateRunning{}},
		})
	}
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{UID: types.UID(uid), Namespace: namespace, Labels: podLabels},
		Status:     v1.PodStatus{ContainerStatuses: statuses},
	}
}

// T5: the pod-event handler routes a matching pod's containers through the
// registry to the policy's reconciler, which resolves each container's root and
// attaches; a delete detaches them.
func TestUprobePodEventHandlers(t *testing.T) {
	reg := newUprobeReconcilerRegistry()
	att := newFakeAttacher()
	reg.register("policyA", newContainerUprobeReconciler("/procRoot", []string{"/lib/a.so"}, att, fakeResolveRoot()), matchAllPods)

	h := newUprobePodHandlers(reg)

	pod := runningPod("uid-1", "abc", "def")
	h.onAdd(pod)

	require.ElementsMatch(t, []string{"uid-1/abc", "uid-1/def"}, att.attachedKeys())
	require.Equal(t, []string{"/procRoot/abc/root/lib/a.so"}, att.pathsOf("uid-1/abc"))
	require.Equal(t, []string{"/procRoot/def/root/lib/a.so"}, att.pathsOf("uid-1/def"))

	// deleting the pod detaches its containers.
	h.onDelete(pod)
	require.Empty(t, att.attachedKeys())
}

// E: a pod update that drops a (terminated) container detaches it, while the
// still-running container stays attached.
func TestUprobePodEventHandlersUpdateDetachesRemoved(t *testing.T) {
	reg := newUprobeReconcilerRegistry()
	att := newFakeAttacher()
	reg.register("policyA", newContainerUprobeReconciler("/procRoot", []string{"/lib/a.so"}, att, fakeResolveRoot()), matchAllPods)
	h := newUprobePodHandlers(reg)

	oldPod := runningPod("uid-1", "abc", "def")
	h.onAdd(oldPod)
	require.ElementsMatch(t, []string{"uid-1/abc", "uid-1/def"}, att.attachedKeys())

	// "def" terminated: the updated pod only lists "abc" as running.
	newPod := runningPod("uid-1", "abc")
	h.onUpdate(oldPod, newPod)
	require.Equal(t, []string{"uid-1/abc"}, att.attachedKeys(),
		"a container removed on update must be detached")
}

// A pod relabeled out of the policy's podSelector must have its containers
// detached, even though the containers themselves keep running.
func TestUprobePodEventHandlersUpdateDetachesOnLabelChange(t *testing.T) {
	reg := newUprobeReconcilerRegistry()
	att := newFakeAttacher()
	match := func(_ string, lbls map[string]string) bool { return lbls["app"] == "sshd" }
	reg.register("policyA", newContainerUprobeReconciler("/procRoot", []string{"/lib/a.so"}, att, fakeResolveRoot()), match)
	h := newUprobePodHandlers(reg)

	oldPod := labeledPod("uid-1", "ns", map[string]string{"app": "sshd"}, "abc", "def")
	h.onAdd(oldPod)
	require.ElementsMatch(t, []string{"uid-1/abc", "uid-1/def"}, att.attachedKeys())

	// relabel the (still-running) pod so it no longer matches the selector.
	newPod := labeledPod("uid-1", "ns", map[string]string{"app": "nginx"}, "abc", "def")
	h.onUpdate(oldPod, newPod)
	require.Empty(t, att.attachedKeys(),
		"a pod relabeled out of the selector must detach its containers")
}

// A pod delete usually carries only terminated container statuses; the detach
// must not depend on the event still listing the containers as running.
func TestUprobePodEventHandlersDeleteTerminatedContainers(t *testing.T) {
	reg := newUprobeReconcilerRegistry()
	att := newFakeAttacher()
	reg.register("policyA", newContainerUprobeReconciler("/procRoot", []string{"/lib/a.so"}, att, fakeResolveRoot()), matchAllPods)
	h := newUprobePodHandlers(reg)

	h.onAdd(runningPod("uid-1", "abc", "def"))
	h.onAdd(runningPod("uid-2", "zzz"))
	require.ElementsMatch(t, []string{"uid-1/abc", "uid-1/def", "uid-2/zzz"}, att.attachedKeys())

	// the delete event reports uid-1's containers as terminated, not running.
	deleted := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{UID: types.UID("uid-1")},
		Status: v1.PodStatus{ContainerStatuses: []v1.ContainerStatus{
			{
				ContainerID: "containerd://abc",
				State:       v1.ContainerState{Terminated: &v1.ContainerStateTerminated{}},
			},
			{
				ContainerID: "containerd://def",
				State:       v1.ContainerState{Terminated: &v1.ContainerStateTerminated{}},
			},
		}},
	}
	h.onDelete(deleted)
	require.Equal(t, []string{"uid-2/zzz"}, att.attachedKeys(),
		"a deleted pod's child sensors must be detached even when its containers are terminated, without touching other pods")
}

// T5: a pod that matches no policy produces no attaches.
func TestUprobePodEventHandlersNoMatch(t *testing.T) {
	reg := newUprobeReconcilerRegistry()
	att := newFakeAttacher()
	reg.register("policyA", newContainerUprobeReconciler("/procRoot", []string{"/lib/a.so"}, att, fakeResolveRoot()),
		func(string, map[string]string) bool { return false })

	h := newUprobePodHandlers(reg)

	h.onAdd(runningPod("uid-1", "abc"))
	require.Empty(t, att.attachedKeys())
}

func TestUprobePodUpdateInvalidatesAllSnapshotsBeforeDetach(t *testing.T) {
	reg := newUprobeReconcilerRegistry()
	release := make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	attA := &blockingDetachAttacher{
		fakeAttacher: newFakeAttacher(),
		started:      make(chan struct{}),
		release:      release,
	}
	attB := &blockingDetachAttacher{
		fakeAttacher: newFakeAttacher(),
		started:      make(chan struct{}),
		release:      release,
	}
	match := func(_ string, labels map[string]string) bool { return labels["selected"] == "true" }
	recA := newContainerUprobeReconciler("/procRoot", []string{"/lib/a.so"}, attA, fakeResolveRoot())
	recB := newContainerUprobeReconciler("/procRoot", []string{"/lib/b.so"}, attB, fakeResolveRoot())
	reg.register("policyA", recA, match)
	reg.register("policyB", recB, match)
	h := newUprobePodHandlers(reg)

	selected := labeledPod("uid-1", "ns", map[string]string{"selected": "true"}, "abc")
	unselected := labeledPod("uid-1", "ns", map[string]string{"selected": "false"}, "abc")
	h.onAdd(selected)
	snapshot := reg.beginSnapshot()
	tokens := make(map[*containerUprobeReconciler]reconcileSnapshotToken)
	for _, entry := range snapshot {
		tokens[entry.r] = entry.token
	}

	done := make(chan struct{})
	go func() {
		h.onUpdate(selected, unselected)
		close(done)
	}()

	var other *containerUprobeReconciler
	select {
	case <-attA.started:
		other = recB
	case <-attB.started:
		other = recA
	case <-time.After(time.Second):
		t.Fatal("pod update did not begin detaching")
	}

	staleDesired := map[string]struct{}{"uid-1/abc": {}}
	require.False(t, other.reconcileContainers(tokens[other], staleDesired),
		"all affected policies must be invalidated before the first slow detach")

	close(release)
	released = true
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("pod update did not finish after detach release")
	}
	require.Empty(t, attA.attachedKeys())
	require.Empty(t, attB.attachedKeys())
}
