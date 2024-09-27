// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package watcher

import (
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics/watchermetrics"
	lru "github.com/hashicorp/golang-lru/v2"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
)

type deletedPodCacheEntry struct {
	pod        *v1.Pod
	contStatus *v1.ContainerStatus
}

type deletedPodCache struct {
	*lru.Cache[string, deletedPodCacheEntry]
}

func newDeletedPodCache() (*deletedPodCache, error) {
	c, err := lru.New[string, deletedPodCacheEntry](128)
	if err != nil {
		return nil, err
	}
	return &deletedPodCache{c}, nil
}

func (c *deletedPodCache) eventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		DeleteFunc: func(obj interface{}) {
			var pod *corev1.Pod
			switch concreteObj := obj.(type) {
			case *corev1.Pod:
				pod = concreteObj
			case cache.DeletedFinalStateUnknown:
				// Handle the case when the watcher missed the deletion event
				// (e.g. due to a lost apiserver connection).
				deletedObj, ok := concreteObj.Obj.(*corev1.Pod)
				if !ok {
					return
				}
				pod = deletedObj
			default:
				return
			}

			run := func(s []v1.ContainerStatus) {
				for i := range s {
					contStatus := &s[i]
					contID := contStatus.ContainerID
					if contID == "" {
						continue
					}

					key, err := containerIDKey(contID)
					if err != nil {
						logger.GetLogger().Warn("failed to crate container key for id '%s': %w", contID, err)
						continue
					}

					c.Add(key, deletedPodCacheEntry{
						pod:        pod,
						contStatus: contStatus,
					})
				}
			}

			run(pod.Status.InitContainerStatuses)
			run(pod.Status.ContainerStatuses)
			run(pod.Status.EphemeralContainerStatuses)
		},
	}
}

func (c *deletedPodCache) findContainer(containerID string) (*corev1.Pod, *corev1.ContainerStatus, bool) {
	v, ok := c.Get(containerID)
	if !ok {
		return nil, nil, false
	}

	watchermetrics.GetWatcherDeletedPodCacheHits().Inc()
	return v.pod, v.contStatus, true
}
