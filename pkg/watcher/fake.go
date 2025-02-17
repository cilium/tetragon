// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package watcher

import (
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/tetragon/pkg/k8s/client/informers/externalversions"
)

// FakeK8sWatcher is used as an "empty" PodAccessor when --enable-k8s-api flag is not set.
// It is also used for testing, allowing users to specify a static list of pods.
type FakeK8sWatcher struct {
	pods     []interface{}
	services []interface{}
}

// NewFakeK8sWatcher returns a pointer to an initialized FakeK8sWatcher struct.
func NewFakeK8sWatcher(pods []interface{}) *FakeK8sWatcher {
	return NewFakeK8sWatcherWithPodsAndServices(pods, nil)
}

// NewFakeK8sWatcherWithPodsAndServices returns a pointer to an initialized FakeK8sWatcher struct
func NewFakeK8sWatcherWithPodsAndServices(pods []interface{}, services []interface{}) *FakeK8sWatcher {
	return &FakeK8sWatcher{pods, services}
}

// FindContainer implements PodAccessor.FindContainer
func (watcher *FakeK8sWatcher) FindContainer(containerID string) (*corev1.Pod, *corev1.ContainerStatus, bool) {
	return findContainer(containerID, watcher.pods)
}
func (watcher *FakeK8sWatcher) FindMirrorPod(_ string) (*corev1.Pod, error) {
	return nil, errors.New("fake watcher does not implement FindMirrorPod")
}

func (watcher *FakeK8sWatcher) FindPod(podID string) (*corev1.Pod, error) {
	ret, ok := findPod(podID, watcher.pods)
	if ok {
		return ret, nil
	}
	return nil, fmt.Errorf("podID %s not found (in %d pods)", podID, len(watcher.pods))
}

// AddPod adds a pod to the fake k8s watcher. This is intended for testing.
func (watcher *FakeK8sWatcher) AddPod(pod *corev1.Pod) {
	watcher.pods = append(watcher.pods, pod)
}

// ClearPods() removes all pods from the fake watcher. This is intended for testing.
func (watcher *FakeK8sWatcher) ClearAllPods() {
	watcher.pods = nil
}

// AddService adds a service to the fake k8s watcher.
func (watcher *FakeK8sWatcher) AddService(service *corev1.Service) {
	watcher.services = append(watcher.services, service)
}

// ClearAllServices removes all services from the fake watcher.
func (watcher *FakeK8sWatcher) ClearAllServices() {
	watcher.services = nil
}

func (watcher *FakeK8sWatcher) AddInformer(_ string, _ cache.SharedIndexInformer, _ cache.Indexers) error {
	return nil
}

func (watcher *FakeK8sWatcher) GetInformer(_ string) cache.SharedIndexInformer {
	return nil
}

func (watcher *FakeK8sWatcher) Start() {}

func (watcher *FakeK8sWatcher) GetK8sInformerFactory() informers.SharedInformerFactory {
	return nil
}

func (watcher *FakeK8sWatcher) GetLocalK8sInformerFactory() informers.SharedInformerFactory {
	return nil
}

func (watcher *FakeK8sWatcher) GetCRDInformerFactory() externalversions.SharedInformerFactory {
	return nil
}
