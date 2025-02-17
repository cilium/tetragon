// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package watcher

import (
	"errors"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/tetragon/pkg/podhooks"
)

const (
	containerIDLen  = 15
	containerIdx    = "containers-ids"
	podIdx          = "pod-ids"
	podInformerName = "pod"
)

var (
	errNoPod = errors.New("object is not a *corev1.Pod")
)

type K8sResourceWatcher interface {
	Watcher
	PodAccessor
}

// PodAccessor defines an interface for accessing pods from Kubernetes API.
type PodAccessor interface {
	// Find a pod/container pair for the given container ID.
	FindContainer(containerID string) (*corev1.Pod, *corev1.ContainerStatus, bool)
	// Find a pod given the podID
	FindPod(podID string) (*corev1.Pod, error)
	// Find a mirror pod for a static pod
	FindMirrorPod(hash string) (*corev1.Pod, error)
}

func AddPodInformer(w *K8sWatcher, local bool) error {
	if w == nil {
		return fmt.Errorf("k8s watcher not initialized")
	}
	factory := w.GetK8sInformerFactory()
	if local {
		factory = w.GetLocalK8sInformerFactory()
	}
	if factory == nil {
		return fmt.Errorf("k8s informer factory not initialized")
	}

	// initialize deleted pod cache
	var err error
	w.deletedPodCache, err = newDeletedPodCache()
	if err != nil {
		return fmt.Errorf("failed to initialize deleted pod cache: %w", err)
	}

	// add informer to the watcher
	informer := factory.Core().V1().Pods().Informer()
	w.AddInformer(podInformerName, informer, map[string]cache.IndexFunc{
		containerIdx: containerIndexFunc,
		podIdx:       podIndexFunc,
	})

	// add event handlers to the informer
	informer.AddEventHandler(w.deletedPodCache.eventHandler())
	podhooks.InstallHooks(informer)

	return nil
}

func containerIDKey(contID string) (string, error) {
	parts := strings.Split(contID, "//")
	if len(parts) != 2 {
		return "", fmt.Errorf("unexpected containerID format, expecting 'docker://<name>', got %q", contID)
	}
	cid := parts[1]
	if len(cid) > containerIDLen {
		cid = cid[:containerIDLen]
	}
	return cid, nil

}

// containerIndexFunc index pod by container IDs.
func containerIndexFunc(obj interface{}) ([]string, error) {
	var containerIDs []string
	putContainer := func(fullContainerID string) error {
		if fullContainerID == "" {
			// This is expected if the container hasn't been started. This function
			// will get called again after the container starts, so we just need to
			// be patient.
			return nil
		}
		cid, err := containerIDKey(fullContainerID)
		if err != nil {
			return err
		}
		containerIDs = append(containerIDs, cid)
		return nil
	}

	switch t := obj.(type) {
	case *corev1.Pod:
		for _, container := range t.Status.InitContainerStatuses {
			err := putContainer(container.ContainerID)
			if err != nil {
				return nil, err
			}
		}
		for _, container := range t.Status.ContainerStatuses {
			err := putContainer(container.ContainerID)
			if err != nil {
				return nil, err
			}
		}
		for _, container := range t.Status.EphemeralContainerStatuses {
			err := putContainer(container.ContainerID)
			if err != nil {
				return nil, err
			}
		}
		return containerIDs, nil
	}
	return nil, fmt.Errorf("%w - found %T", errNoPod, obj)
}

func podIndexFunc(obj interface{}) ([]string, error) {
	switch t := obj.(type) {
	case *corev1.Pod:
		return []string{string(t.UID)}, nil
	}
	return nil, fmt.Errorf("podIndexFunc: %w - found %T", errNoPod, obj)
}

// FindContainer implements PodAccessor.FindContainer.
func (watcher *K8sWatcher) FindContainer(containerID string) (*corev1.Pod, *corev1.ContainerStatus, bool) {
	podInformer := watcher.GetInformer(podInformerName)
	if podInformer == nil {
		return nil, nil, false
	}
	indexedContainerID := containerID
	if len(containerID) > containerIDLen {
		indexedContainerID = containerID[:containerIDLen]
	}
	objs, err := podInformer.GetIndexer().ByIndex(containerIdx, indexedContainerID)
	if err != nil {
		return nil, nil, false
	}
	// If we can't find any pod indexed then fall back to the entire pod list.
	// If we find more than 1 pods indexed also fall back to the entire pod list.
	if len(objs) != 1 {
		objs = podInformer.GetStore().List()
	}
	pod, cont, found := findContainer(containerID, objs)
	if found {
		return pod, cont, found
	}

	return watcher.deletedPodCache.findContainer(indexedContainerID)
}

// TODO(michi) Not the most efficient implementation. Optimize as needed.
func findContainer(containerID string, pods []interface{}) (*corev1.Pod, *corev1.ContainerStatus, bool) {
	if containerID == "" {
		return nil, nil, false
	}
	for _, obj := range pods {
		pod, ok := obj.(*corev1.Pod)
		if !ok {
			return nil, nil, false
		}
		for _, container := range pod.Status.ContainerStatuses {
			parts := strings.Split(container.ContainerID, "//")
			if len(parts) == 2 && strings.HasPrefix(parts[1], containerID) {
				return pod, &container, true
			}
		}
		for _, container := range pod.Status.InitContainerStatuses {
			parts := strings.Split(container.ContainerID, "//")
			if len(parts) == 2 && strings.HasPrefix(parts[1], containerID) {
				return pod, &container, true
			}
		}
		for _, container := range pod.Status.EphemeralContainerStatuses {
			parts := strings.Split(container.ContainerID, "//")
			if len(parts) == 2 && strings.HasPrefix(parts[1], containerID) {
				return pod, &container, true
			}
		}
	}
	return nil, nil, false
}

// FindMirrorPod finds the mirror pod of a static pod based on the hash
// see: https://kubernetes.io/docs/reference/labels-annotations-taints/#kubernetes-io-config-hash,
// https://kubernetes.io/docs/reference/labels-annotations-taints/#kubernetes-io-config-mirror,
// https://kubernetes.io/docs/tasks/configure-pod-container/static-pod/
func (watcher *K8sWatcher) FindMirrorPod(hash string) (*corev1.Pod, error) {
	podInformer := watcher.GetInformer(podInformerName)
	if podInformer == nil {
		return nil, fmt.Errorf("pod informer not initialized")
	}
	pods := podInformer.GetStore().List()
	for i := range pods {
		if pod, ok := pods[i].(*corev1.Pod); ok {
			if ha, ok := pod.Annotations["kubernetes.io/config.mirror"]; ok {
				if hash == ha {
					return pod, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("static pod (hash=%s) not found", hash)
}

func (watcher *K8sWatcher) FindPod(podID string) (*corev1.Pod, error) {
	podInformer := watcher.GetInformer(podInformerName)
	if podInformer == nil {
		return nil, fmt.Errorf("pod informer not initialized")
	}
	objs, err := podInformer.GetIndexer().ByIndex(podIdx, podID)
	if err != nil {
		return nil, fmt.Errorf("watcher returned: %w", err)
	}
	if len(objs) == 1 {
		if pod, ok := objs[0].(*corev1.Pod); ok {
			return pod, nil
		}
		return nil, fmt.Errorf("unexpected type %t", objs[0])
	}

	allPods := podInformer.GetStore().List()
	if pod, ok := findPod(allPods); ok {
		return pod, nil
	}
	return nil, fmt.Errorf("unable to find pod with ID %s (index pods=%d all pods=%d)", podID, len(objs), len(allPods))
}

func findPod(pods []interface{}) (*corev1.Pod, bool) {
	for i := range pods {
		if pod, ok := pods[i].(*corev1.Pod); ok {
			if pod.UID == podIdx {
				return pod, true
			}
		}
	}

	return nil, false
}
