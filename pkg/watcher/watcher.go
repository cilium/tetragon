// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package watcher

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/cilium/tetragon/pkg/logger"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	containerIDLen = 15
	containerIdx   = "containers-ids"
)

var (
	errNoPod = errors.New("object is not a *corev1.Pod")
)

// K8sResourceWatcher defines an interface for accessing various resources from Kubernetes API.
type K8sResourceWatcher interface {
	// Find a pod/container pair for the given container ID.
	FindPod(containerID string) (*corev1.Pod, *corev1.ContainerStatus, bool)
}

// K8sWatcher maintains a local cache of k8s resources.
type K8sWatcher struct {
	podInformer cache.SharedIndexInformer
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
		parts := strings.Split(fullContainerID, "//")
		if len(parts) != 2 {
			return fmt.Errorf("unexpected containerID format, expecting 'docker://<name>', got %q", fullContainerID)
		}
		cid := parts[1]
		if len(cid) > containerIDLen {
			cid = cid[:containerIDLen]
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

// NewK8sWatcher returns a pointer to an initialized K8sWatcher struct.
func NewK8sWatcher(k8sClient kubernetes.Interface, stateSyncIntervalSec time.Duration) *K8sWatcher {
	k8sInformerFactory := informers.NewSharedInformerFactoryWithOptions(k8sClient, stateSyncIntervalSec,
		informers.WithTweakListOptions(func(options *metav1.ListOptions) {
			// Watch local pods only.
			options.FieldSelector = "spec.nodeName=" + os.Getenv("NODE_NAME")
		}))
	podInformer := k8sInformerFactory.Core().V1().Pods().Informer()

	err := podInformer.AddIndexers(map[string]cache.IndexFunc{
		containerIdx: containerIndexFunc,
	})
	if err != nil {
		// Panic during setup since this should never fail, if it fails is a
		// developer mistake.
		panic(err)
	}
	k8sInformerFactory.Start(wait.NeverStop)
	k8sInformerFactory.WaitForCacheSync(wait.NeverStop)
	logger.GetLogger().WithField("num_pods", len(podInformer.GetStore().ListKeys())).Info("Initialized pod cache")
	return &K8sWatcher{podInformer: podInformer}
}

// FindPod implements K8sResourceWatcher.FindPod.
func (watcher *K8sWatcher) FindPod(containerID string) (*corev1.Pod, *corev1.ContainerStatus, bool) {
	indexedContainerID := containerID
	if len(containerID) > containerIDLen {
		indexedContainerID = containerID[:containerIDLen]
	}
	objs, err := watcher.podInformer.GetIndexer().ByIndex(containerIdx, indexedContainerID)
	if err != nil {
		return nil, nil, false
	}
	// If we can't find any pod indexed then fall back to the entire pod list.
	// If we find more than 1 pods indexed also fall back to the entire pod list.
	if len(objs) != 1 {
		return findContainer(containerID, watcher.podInformer.GetStore().List())
	}
	return findContainer(containerID, objs)
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
