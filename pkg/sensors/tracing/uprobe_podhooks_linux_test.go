// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows && !nok8s

package tracing

import (
	"testing"

	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
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
		UID: types.UID(uid), Namespace: namespace, Labels: podLabels,
		Status: v1.PodStatus{ContainerStatuses: statuses},
	}
}

// newTestPodHandlers wires one policy whose matcher is match, over container
// roots holding the uprobe target.
func newTestPodHandlers(t *testing.T, match podMatcher) (*uprobePodHandlers, *fakeAttacher, *containerRoots) {
	t.Helper()
	const target = "/lib/a.so"
	reg := newUprobeReconcilerRegistry()
	att := newFakeAttacher()
	roots := newContainerRoots(t, target)
	reg.register("policyA", newContainerUprobeReconciler("", target, att, roots.resolver()), match)
	return newUprobePodHandlers(reg), att, roots
}

// the pod-event handler routes a matching pod's containers through the
// registry to the policy's reconciler, which resolves each container's root and
// attaches; a delete detaches them.
func TestUprobePodEventHandlers(t *testing.T) {
	h, att, roots := newTestPodHandlers(t, matchAllPods)

	pod := runningPod("uid-1", "abc", "def")
	h.onAdd(pod)

	require.ElementsMatch(t, []string{"uid-1/abc", "uid-1/def"}, att.attachedKeys())
	require.Equal(t, roots.binary("abc"), att.pathOf("uid-1/abc"))
	require.Equal(t, roots.binary("def"), att.pathOf("uid-1/def"))

	// deleting the pod detaches its containers.
	h.onDelete(pod)
	require.Empty(t, att.attachedKeys())
}

// a pod update that drops a (terminated) container detaches it, while the
// still-running container stays attached.
func TestUprobePodEventHandlersUpdateDetachesRemoved(t *testing.T) {
	h, att, _ := newTestPodHandlers(t, matchAllPods)

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
	h, att, _ := newTestPodHandlers(t, func(_ string, lbls map[string]string) bool {
		return lbls["app"] == "sshd"
	})

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
	h, att, _ := newTestPodHandlers(t, matchAllPods)

	h.onAdd(runningPod("uid-1", "abc", "def"))
	h.onAdd(runningPod("uid-2", "zzz"))
	require.ElementsMatch(t, []string{"uid-1/abc", "uid-1/def", "uid-2/zzz"}, att.attachedKeys())

	// the delete event reports uid-1's containers as terminated, not running.
	deleted := &v1.Pod{
		UID: types.UID("uid-1"),
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
