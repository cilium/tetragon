// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package watcher

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/cilium"
	"github.com/cilium/tetragon/pkg/filters"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics/watchermetrics"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	hubblev1 "github.com/cilium/hubble/pkg/api/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	containerIDLen = 15
	containerIdx   = "containers-ids"
	namespaceIdx   = "namespace-ids"
)

var (
	errNoPod = errors.New("object is not a *corev1.Pod")
)

// K8sResourceWatcher defines an interface for accessing various resources from Kubernetes API.
type K8sResourceWatcher interface {
	// Find Namespace
	FindNamespace(namespace string) []*corev1.Pod

	// Find a pod/container pair for the given container ID.
	FindPod(containerID string) (*corev1.Pod, *corev1.ContainerStatus, bool)

	// Get PodInfo and Endpoint ID for a containerId.
	GetPodInfo(containerID, binary, args string, nspid uint32) (*tetragon.Pod, *hubblev1.Endpoint)
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

func GetPodIds(pods []*corev1.Pod) ([]string, error) {
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

	for _, pod := range pods {
		for _, container := range pod.Status.InitContainerStatuses {
			err := putContainer(container.ContainerID)
			if err != nil {
				return nil, err
			}
		}
		for _, container := range pod.Status.ContainerStatuses {
			err := putContainer(container.ContainerID)
			if err != nil {
				return nil, err
			}
		}
		for _, container := range pod.Status.EphemeralContainerStatuses {
			err := putContainer(container.ContainerID)
			if err != nil {
				return nil, err
			}
		}
		return containerIDs, nil
	}
	return containerIDs, nil
}

// namespaceIndexFunc index pod by namespaces.
func namespaceIndexFunc(obj interface{}) ([]string, error) {
	var names []string

	switch t := obj.(type) {
	case *corev1.Pod:
		names = append(names, t.Namespace)
		return names, nil
	}
	return nil, fmt.Errorf("%w - found %T", errNoPod, obj)
}

// NewK8sWatcher returns a pointer to an initialized K8sWatcher struct.
func NewK8sWatcher(k8sClient *kubernetes.Clientset, stateSyncIntervalSec time.Duration) *K8sWatcher {
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

	err = podInformer.AddIndexers(map[string]cache.IndexFunc{
		namespaceIdx: namespaceIndexFunc,
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

func (watcher *K8sWatcher) FindNamespace(ns string) []*corev1.Pod {
	var pods []*corev1.Pod

	indexedNamespaceID := ns
	objs, err := watcher.podInformer.GetIndexer().ByIndex(namespaceIdx, indexedNamespaceID)
	if err != nil {
		return pods
	}
	for _, obj := range objs {
		pod, ok := obj.(*corev1.Pod)
		if ok {
			pods = append(pods, pod)
		}
	}
	return pods
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

func (watcher *K8sWatcher) GetPodInfo(containerID string, binary string, args string, nspid uint32) (*tetragon.Pod, *hubblev1.Endpoint) {
	if containerID == "" {
		return nil, nil
	}
	pod, container, ok := watcher.FindPod(containerID)
	if !ok {
		watchermetrics.GetWatcherErrors("k8s", watchermetrics.FailedToGetPodError).Inc()
		logger.GetLogger().WithField("container id", containerID).Trace("failed to get pod")
		return nil, nil
	}
	var startTime *timestamppb.Timestamp
	livenessProbe, readinessProbe := getProbes(pod, container)
	maybeExecProbe := filters.MaybeExecProbe(binary, args, livenessProbe) ||
		filters.MaybeExecProbe(binary, args, readinessProbe)
	if container.State.Running != nil {
		startTime = timestamppb.New(container.State.Running.StartedAt.Time)
	}

	ciliumState := cilium.GetCiliumState()
	endpoint, ok := ciliumState.GetEndpointsHandler().GetEndpointByPodName(pod.Namespace, pod.Name)
	var labels []string
	if ok {
		labels = endpoint.Labels
	}

	// Don't set container PIDs if it's zero.
	var containerPID *wrapperspb.UInt32Value
	if nspid > 0 {
		containerPID = &wrapperspb.UInt32Value{
			Value: nspid,
		}
	}

	watchermetrics.GetWatcherEvents("k8s").Inc()
	return &tetragon.Pod{
		Namespace: pod.Namespace,
		Name:      pod.Name,
		Labels:    labels,
		PodLabels: pod.Labels,
		Container: &tetragon.Container{
			Id:   container.ContainerID,
			Pid:  containerPID,
			Name: container.Name,
			Image: &tetragon.Image{
				Id:   container.ImageID,
				Name: container.Image,
			},
			StartTime:      startTime,
			MaybeExecProbe: maybeExecProbe,
		},
	}, endpoint
}

// FakeK8sWatcher is used as an "empty" K8sResourceWatcher when --enable-k8s-api flag is not set.
type FakeK8sWatcher struct {
	pods []interface{}
}

// NewK8sWatcher returns a pointer to an initialized FakeK8sWatcher struct.
func NewFakeK8sWatcher(pods []interface{}) *FakeK8sWatcher {
	return &FakeK8sWatcher{pods: pods}
}

// FindNamespace impelements K8sResourceWatcher.FindNamespace
func (watcher *FakeK8sWatcher) FindNamespace(ns string) []*corev1.Pod {
	var pods []*corev1.Pod

	return pods
}

// FindPod implements K8sResourceWatcher.FindPod.
func (watcher *FakeK8sWatcher) FindPod(containerID string) (*corev1.Pod, *corev1.ContainerStatus, bool) {
	return findContainer(containerID, watcher.pods)
}

func (watcher *FakeK8sWatcher) GetPodInfo(containerID string, binary string, args string, nspid uint32) (*tetragon.Pod, *hubblev1.Endpoint) {
	pod, container, ok := watcher.FindPod(containerID)
	if !ok {
		watchermetrics.GetWatcherErrors("fake-k8s", watchermetrics.FailedToGetPodError).Inc()
		logger.GetLogger().WithField("container id", containerID).Trace("failed to get pod")
		return nil, nil
	}

	var startTime *timestamppb.Timestamp
	livenessProbe, readinessProbe := getProbes(pod, container)
	maybeExecProbe := filters.MaybeExecProbe(binary, args, livenessProbe) ||
		filters.MaybeExecProbe(binary, args, readinessProbe)
	if container.State.Running != nil {
		startTime = timestamppb.New(container.State.Running.StartedAt.Time)
	}

	var emptyLabels []string

	// Don't set container PIDs if it's zero.
	var containerPID *wrapperspb.UInt32Value
	if nspid > 0 {
		containerPID = &wrapperspb.UInt32Value{
			Value: nspid,
		}
	}

	watchermetrics.GetWatcherEvents("fake-k8s").Inc()
	return &tetragon.Pod{
		Namespace: pod.Namespace,
		Name:      pod.Name,
		Labels:    emptyLabels,
		Container: &tetragon.Container{
			Id:   container.ContainerID,
			Pid:  containerPID,
			Name: container.Name,
			Image: &tetragon.Image{
				Id:   container.ImageID,
				Name: container.Image,
			},
			StartTime:      startTime,
			MaybeExecProbe: maybeExecProbe,
		},
	}, nil
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
