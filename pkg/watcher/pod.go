// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package watcher

import (
	"errors"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
)

const (
	containerIDLen  = 15
	ContainerIdx    = "containers-ids"
	PodIdx          = "pod-ids"
	podInformerName = "pod"
)

var (
	errNoPod = errors.New("object is not a *corev1.Pod")
)

// PodAccessor defines an interface for accessing pods from Kubernetes API.
type PodAccessor interface {
	// Find a pod/container pair for the given container ID.
	FindContainer(containerID string) (*corev1.Pod, *corev1.ContainerStatus, bool)
	// Find a pod given the podID
	FindPod(podID string) (*corev1.Pod, error)
	// Find a mirror pod for a static pod
	FindMirrorPod(hash string) (*corev1.Pod, error)
}

func ContainerIDKey(contID string) (string, error) {
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

// ContainerIndexFunc index pod by container IDs.
func ContainerIndexFunc(obj any) ([]string, error) {
	var containerIDs []string
	putContainer := func(fullContainerID string) error {
		if fullContainerID == "" {
			// This is expected if the container hasn't been started. This function
			// will get called again after the container starts, so we just need to
			// be patient.
			return nil
		}
		cid, err := ContainerIDKey(fullContainerID)
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

func PodIndexFunc(obj any) ([]string, error) {
	switch t := obj.(type) {
	case *corev1.Pod:
		return []string{string(t.UID)}, nil
	}
	return nil, fmt.Errorf("PodIndexFunc: %w - found %T", errNoPod, obj)
}

func FindContainer(containerID string, podInformer cache.SharedIndexInformer, deletedPodCache *DeletedPodCache) (*corev1.Pod, *corev1.ContainerStatus, bool) {
	indexedContainerID := containerID
	if len(containerID) > containerIDLen {
		indexedContainerID = containerID[:containerIDLen]
	}
	objs, err := podInformer.GetIndexer().ByIndex(ContainerIdx, indexedContainerID)
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

	return deletedPodCache.FindContainer(indexedContainerID)
}

// TODO(michi) Not the most efficient implementation. Optimize as needed.
func findContainer(containerID string, pods []any) (*corev1.Pod, *corev1.ContainerStatus, bool) {
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

func FindMirrorPod(hash string, podInformer cache.SharedIndexInformer) (*corev1.Pod, error) {
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

func FindPod(podID string, podInformer cache.SharedIndexInformer) (*corev1.Pod, error) {
	// First try to find the pod by index
	objs, err := podInformer.GetIndexer().ByIndex(PodIdx, podID)
	if err != nil {
		return nil, fmt.Errorf("watcher returned: %w", err)
	}
	if len(objs) == 1 {
		if pod, ok := objs[0].(*corev1.Pod); ok {
			return pod, nil
		}
		return nil, fmt.Errorf("unexpected type %t", objs[0])
	}

	// If unsuccessful, fall back to walking the entire pod list
	allPods := podInformer.GetStore().List()
	if pod, ok := findPod(podID, allPods); ok {
		return pod, nil
	}
	return nil, fmt.Errorf("unable to find pod with ID %s (index pods=%d all pods=%d)", podID, len(objs), len(allPods))
}

func findPod(podID string, pods []any) (*corev1.Pod, bool) {
	for i := range pods {
		if pod, ok := pods[i].(*corev1.Pod); ok {
			if string(pod.UID) == podID {
				return pod, true
			}
		}
	}

	return nil, false
}
