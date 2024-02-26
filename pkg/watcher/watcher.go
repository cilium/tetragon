// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package watcher

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/k8s/client/clientset/versioned"
	"github.com/cilium/tetragon/pkg/k8s/client/clientset/versioned/fake"
	"github.com/cilium/tetragon/pkg/k8s/client/informers/externalversions"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/podhooks"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

const (
	containerIDLen = 15
	containerIdx   = "containers-ids"
	podIdx         = "pod-ids"
	serviceIPsIdx  = "service-ips"
	podInfoIPsIdx  = "pod-info-ips"
)

var (
	errNoPod     = errors.New("object is not a *corev1.Pod")
	errNoService = errors.New("object is not a *corev1.Service")
	errNoPodInfo = errors.New("object is not a *PodInfo")
)

// K8sResourceWatcher defines an interface for accessing various resources from Kubernetes API.
type K8sResourceWatcher interface {
	// Find a pod/container pair for the given container ID.
	FindContainer(containerID string) (*corev1.Pod, *corev1.ContainerStatus, bool)

	// Find a pod given the podID
	FindPod(podID string) (*corev1.Pod, error)
}

// K8sWatcher maintains a local cache of k8s resources.
type K8sWatcher struct {
	podInformer     cache.SharedIndexInformer
	serviceInformer cache.SharedIndexInformer
	podInfoInformer cache.SharedIndexInformer
}

func podIndexFunc(obj interface{}) ([]string, error) {
	switch t := obj.(type) {
	case *corev1.Pod:
		return []string{string(t.UID)}, nil
	}
	return nil, fmt.Errorf("podIndexFunc: %w - found %T", errNoPod, obj)
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

// serviceIPIndexFunc indexes services by their IP addresses
func serviceIPIndexFunc(obj interface{}) ([]string, error) {
	switch t := obj.(type) {
	case *corev1.Service:
		return t.Spec.ClusterIPs, nil
	}
	return nil, fmt.Errorf("%w - found %T", errNoService, obj)
}

// podInfoIPIndexFunc indexes services by their IP addresses
func podInfoIPIndexFunc(obj interface{}) ([]string, error) {
	switch t := obj.(type) {
	case *v1alpha1.PodInfo:
		var ips []string
		for _, ip := range t.Status.PodIPs {
			ips = append(ips, ip.IP)
		}
		return ips, nil
	}
	return nil, fmt.Errorf("%w - found %T", errNoPodInfo, obj)
}

// NewK8sWatcher returns a pointer to an initialized K8sWatcher struct.
func NewK8sWatcher(k8sClient kubernetes.Interface, stateSyncIntervalSec time.Duration) *K8sWatcher {
	return NewK8sWatcherWithTetragonClient(k8sClient, fake.NewSimpleClientset(), stateSyncIntervalSec)
}

// NewK8sWatcherWithTetragonClient returns a pointer to an initialized K8sWatcher struct.
func NewK8sWatcherWithTetragonClient(k8sClient kubernetes.Interface, tetragonClient versioned.Interface, stateSyncIntervalSec time.Duration) *K8sWatcher {
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		logger.GetLogger().Warn("env var NODE_NAME not specified, K8s watcher will not work as expected")
	}
	k8sInformerFactory := informers.NewSharedInformerFactoryWithOptions(k8sClient, stateSyncIntervalSec,
		informers.WithTweakListOptions(func(options *metav1.ListOptions) {
			// Watch local pods only.
			options.FieldSelector = "spec.nodeName=" + os.Getenv("NODE_NAME")
		}))
	podInformer := k8sInformerFactory.Core().V1().Pods().Informer()

	err := podInformer.AddIndexers(map[string]cache.IndexFunc{
		containerIdx: containerIndexFunc,
		podIdx:       podIndexFunc,
	})
	if err != nil {
		// Panic during setup since this should never fail, if it fails is a
		// developer mistake.
		panic(err)
	}

	// can't share the same informer factory as pods because the pod informer filters by spec.nodeName field.
	serviceInformerFactory := informers.NewSharedInformerFactory(k8sClient, stateSyncIntervalSec)
	serviceInformer := serviceInformerFactory.Core().V1().Services().Informer()
	err = serviceInformer.AddIndexers(map[string]cache.IndexFunc{
		serviceIPsIdx: serviceIPIndexFunc,
	})
	if err != nil {
		// Panic during setup since this should never fail, if it fails is a
		// developer mistake.
		panic(err)
	}

	podInfoInformerFactory := externalversions.NewSharedInformerFactory(tetragonClient, stateSyncIntervalSec)
	podInfoInformer := podInfoInformerFactory.Cilium().V1alpha1().PodInfo().Informer()
	err = podInfoInformer.AddIndexers(map[string]cache.IndexFunc{
		podInfoIPsIdx: podInfoIPIndexFunc,
	})
	if err != nil {
		// Panic during setup since this should never fail, if it fails is a
		// developer mistake.
		panic(err)
	}

	podhooks.InstallHooks(podInformer)

	k8sInformerFactory.Start(wait.NeverStop)
	k8sInformerFactory.WaitForCacheSync(wait.NeverStop)
	serviceInformerFactory.Start(wait.NeverStop)
	serviceInformerFactory.WaitForCacheSync(wait.NeverStop)
	podInfoInformerFactory.Start(wait.NeverStop)
	podInfoInformerFactory.WaitForCacheSync(wait.NeverStop)
	logger.GetLogger().WithField("num_pods", len(podInformer.GetStore().ListKeys())).Info("Initialized pod cache")
	logger.GetLogger().WithField("num_services", len(serviceInformer.GetStore().ListKeys())).Info("Initialized service cache")
	logger.GetLogger().WithField("num_pod_info", len(podInfoInformer.GetStore().ListKeys())).Info("Initialized pod info cache")
	return &K8sWatcher{podInformer, serviceInformer, podInfoInformer}
}

// FindContainer implements K8sResourceWatcher.FindContainer.
func (watcher *K8sWatcher) FindContainer(containerID string) (*corev1.Pod, *corev1.ContainerStatus, bool) {
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

func (watcher *K8sWatcher) FindPod(podID string) (*corev1.Pod, error) {
	objs, err := watcher.podInformer.GetIndexer().ByIndex(podIdx, podID)
	if err != nil {
		return nil, fmt.Errorf("watcher returned: %w", err)
	}
	if len(objs) == 1 {
		if pod, ok := objs[0].(*corev1.Pod); ok {
			return pod, nil
		}
		return nil, fmt.Errorf("unexpected type %t", objs[0])
	}

	allPods := watcher.podInformer.GetStore().List()
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
