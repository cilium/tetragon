// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package watcher

import corev1 "k8s.io/api/core/v1"

// FakeK8sWatcher is used as an "empty" K8sResourceWatcher when --enable-k8s-api flag is not set.
// It is also used for testing, allowing users to specify a static list of pods.
type FakeK8sWatcher struct {
	pods []interface{}
}

// NewK8sWatcher returns a pointer to an initialized FakeK8sWatcher struct.
func NewFakeK8sWatcher(pods []interface{}) *FakeK8sWatcher {
	return &FakeK8sWatcher{pods: pods}
}

// FindPod implements K8sResourceWatcher.FindPod.
func (watcher *FakeK8sWatcher) FindPod(containerID string) (*corev1.Pod, *corev1.ContainerStatus, bool) {
	return findContainer(containerID, watcher.pods)
}

// AddPod adds a pod to the fake k8s watcher. This is intended for testing.
func (watcher *FakeK8sWatcher) AddPod(pod *corev1.Pod) {
	watcher.pods = append(watcher.pods, pod)
}

// ClearPods() removes all pods from the fake watcher. This is intended for testing.
func (watcher *FakeK8sWatcher) ClearAllPods() {
	watcher.pods = nil
}
