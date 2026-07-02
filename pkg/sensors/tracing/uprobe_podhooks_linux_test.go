// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows && !nok8s

package tracing

import (
	"testing"

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
	reg.register("policyA", newContainerUprobeReconciler("/procRoot", []ricTarget{{path: "/lib/a.so"}}, att, fakeResolveRoot()), matchAllPods)

	h := newUprobePodHandlers(reg)

	pod := runningPod("uid-1", "abc", "def")
	h.onAdd(pod)

	require.ElementsMatch(t, []string{"uid-1/abc", "uid-1/def"}, att.attachedKeys())
	require.Equal(t, "/procRoot/abc/root/lib/a.so", att.pathOf("uid-1/abc"))
	require.Equal(t, "/procRoot/def/root/lib/a.so", att.pathOf("uid-1/def"))

	// deleting the pod detaches its containers.
	h.onDelete(pod)
	require.Empty(t, att.attachedKeys())
}

// E: a pod update that drops a (terminated) container detaches it, while the
// still-running container stays attached.
func TestUprobePodEventHandlersUpdateDetachesRemoved(t *testing.T) {
	reg := newUprobeReconcilerRegistry()
	att := newFakeAttacher()
	reg.register("policyA", newContainerUprobeReconciler("/procRoot", []ricTarget{{path: "/lib/a.so"}}, att, fakeResolveRoot()), matchAllPods)
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
	reg.register("policyA", newContainerUprobeReconciler("/procRoot", []ricTarget{{path: "/lib/a.so"}}, att, fakeResolveRoot()), match)
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

// T5: a pod that matches no policy produces no attaches.
func TestUprobePodEventHandlersNoMatch(t *testing.T) {
	reg := newUprobeReconcilerRegistry()
	att := newFakeAttacher()
	reg.register("policyA", newContainerUprobeReconciler("/procRoot", []ricTarget{{path: "/lib/a.so"}}, att, fakeResolveRoot()),
		func(string, map[string]string) bool { return false })

	h := newUprobePodHandlers(reg)

	h.onAdd(runningPod("uid-1", "abc"))
	require.Empty(t, att.attachedKeys())
}
