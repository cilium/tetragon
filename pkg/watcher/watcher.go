// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package watcher

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/podhooks"
	"github.com/cilium/tetragon/pkg/reader/node"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

const (
	containerIDLen  = 15
	containerIdx    = "containers-ids"
	podIdx          = "pod-ids"
	serviceIPsIdx   = "service-ips"
	podInfoIPsIdx   = "pod-info-ips"
	podInformerName = "pod"
)

var (
	errNoPod = errors.New("object is not a *corev1.Pod")
)

// K8sResourceWatcher defines an interface for accessing various resources from Kubernetes API.
type K8sResourceWatcher interface {
	AddInformers(factory InternalSharedInformerFactory, infs ...*InternalInformer)
	GetInformer(name string) cache.SharedIndexInformer
	Start()

	// Find a pod/container pair for the given container ID.
	FindContainer(containerID string) (*corev1.Pod, *corev1.ContainerStatus, bool)

	// Find a pod given the podID
	FindPod(podID string) (*corev1.Pod, error)
	// Find a mirror pod for a static pod
	FindMirrorPod(hash string) (*corev1.Pod, error)
}

// K8sWatcher maintains a local cache of k8s resources.
type K8sWatcher struct {
	informers       map[string]cache.SharedIndexInformer
	startFunc       func()
	deletedPodCache *deletedPodCache
}

type InternalSharedInformerFactory interface {
	Start(stopCh <-chan struct{})
	WaitForCacheSync(stopCh <-chan struct{}) map[reflect.Type]bool
}

type InternalInformer struct {
	Name     string
	Informer cache.SharedIndexInformer
	Indexers cache.Indexers
}

func podIndexFunc(obj interface{}) ([]string, error) {
	switch t := obj.(type) {
	case *corev1.Pod:
		return []string{string(t.UID)}, nil
	}
	return nil, fmt.Errorf("podIndexFunc: %w - found %T", errNoPod, obj)
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

func newK8sWatcher(
	informerFactory informers.SharedInformerFactory,
) (*K8sWatcher, error) {

	deletedPodCache, err := newDeletedPodCache()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize deleted pod cache: %w", err)
	}

	k8sWatcher := &K8sWatcher{
		informers:       make(map[string]cache.SharedIndexInformer),
		startFunc:       func() {},
		deletedPodCache: deletedPodCache,
	}

	podInformer := informerFactory.Core().V1().Pods().Informer()
	k8sWatcher.AddInformers(informerFactory, &InternalInformer{
		Name:     podInformerName,
		Informer: podInformer,
		Indexers: map[string]cache.IndexFunc{
			containerIdx: containerIndexFunc,
			podIdx:       podIndexFunc,
		},
	})
	podInformer.AddEventHandler(k8sWatcher.deletedPodCache.eventHandler())
	podhooks.InstallHooks(podInformer)

	return k8sWatcher, nil
}

// NewK8sWatcher returns a pointer to an initialized K8sWatcher struct.
func NewK8sWatcher(k8sClient kubernetes.Interface, stateSyncIntervalSec time.Duration) (*K8sWatcher, error) {
	nodeName := node.GetNodeNameForExport()
	if nodeName == "" {
		logger.GetLogger().Warn("env var NODE_NAME not specified, K8s watcher will not work as expected")
	}

	informerFactory := informers.NewSharedInformerFactoryWithOptions(k8sClient, stateSyncIntervalSec,
		informers.WithTweakListOptions(func(options *metav1.ListOptions) {
			// Watch local pods only.
			options.FieldSelector = "spec.nodeName=" + nodeName
		}))

	return newK8sWatcher(informerFactory)
}

func (watcher *K8sWatcher) AddInformers(factory InternalSharedInformerFactory, infs ...*InternalInformer) {
	if watcher.startFunc == nil {
		watcher.startFunc = func() {}
	}
	// Add informers
	for _, inf := range infs {
		watcher.informers[inf.Name] = inf.Informer
		oldStart := watcher.startFunc
		watcher.startFunc = func() {
			oldStart()
			err := inf.Informer.AddIndexers(inf.Indexers)
			if err != nil {
				// Panic during setup since this should never fail, if it fails is a
				// developer mistake.
				panic(err)
			}
		}
	}
	// Start the informer factory
	oldStart := watcher.startFunc
	watcher.startFunc = func() {
		oldStart()
		factory.Start(wait.NeverStop)
		factory.WaitForCacheSync(wait.NeverStop)
		for name, informer := range watcher.informers {
			logger.GetLogger().WithField("informer", name).WithField("count", len(informer.GetStore().ListKeys())).Info("Initialized informer cache")
		}
	}
}

func (watcher *K8sWatcher) GetInformer(name string) cache.SharedIndexInformer {
	return watcher.informers[name]
}

func (watcher *K8sWatcher) Start() {
	if watcher.startFunc != nil {
		watcher.startFunc()
	}
}

// FindContainer implements K8sResourceWatcher.FindContainer.
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

	// First try to find the pod by index
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

	// If unsuccessful, fall back to walking the entire pod list
	allPods := podInformer.GetStore().List()
	if pod, ok := findPod(podID, allPods); ok {
		return pod, nil
	}
	return nil, fmt.Errorf("unable to find pod with ID %s (index pods=%d all pods=%d)", podID, len(objs), len(allPods))
}

func findPod(podID string, pods []interface{}) (*corev1.Pod, bool) {
	for i := range pods {
		if pod, ok := pods[i].(*corev1.Pod); ok {
			if string(pod.UID) == podID {
				return pod, true
			}
		}
	}

	return nil, false
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
