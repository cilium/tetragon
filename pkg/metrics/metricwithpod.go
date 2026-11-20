// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !nok8s

package metrics

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/tetragon/pkg/logger"
)

// PodEventSource is the narrow capability metrics needs from the pod informer:
// a delete callback delivered with a typed `*corev1.Pod`. Defined here, where
// it is consumed, so the metrics package does not depend on `pkg/manager`.
// The concrete adapter lives in `pkg/manager` and satisfies this interface.
type PodEventSource interface {
	OnPodDelete(handler func(pod *corev1.Pod)) error
}

var (
	podQueue     workqueue.TypedDelayingInterface[any]
	podQueueOnce sync.Once
	deleteDelay  = 1 * time.Minute
)

// RegisterPodDeleteHandler registers a handler for deleting metrics associated
// with deleted pods. Without it, Tetragon kept exposing stale metrics for
// deleted pods. This was causing continuous increase in memory usage in
// Tetragon agent as well as in the metrics scraper.
//
// `events` is the typed pod event source provided by `pkg/manager`. Tests can
// pass a hand-rolled fake satisfying the same interface.
func RegisterPodDeleteHandler(events PodEventSource) error {
	logger.GetLogger().Info("Registering pod delete handler for metrics")
	return events.OnPodDelete(func(pod *corev1.Pod) {
		queue := GetPodQueue()
		queue.AddAfter(pod, deleteDelay)
	})
}

func GetPodQueue() workqueue.TypedDelayingInterface[any] {
	podQueueOnce.Do(func() {
		podQueue = workqueue.NewTypedDelayingQueueWithConfig(workqueue.TypedDelayingQueueConfig[any]{Name: "pod-queue"})
	})
	return podQueue
}

func DeleteMetricsForPod(pod *corev1.Pod) {
	for _, metric := range ListMetricsWithPod() {
		metric.DeletePartialMatch(prometheus.Labels{
			"pod":       pod.Name,
			"namespace": pod.Namespace,
		})
	}
}

func StartPodDeleteHandler() {
	queue := GetPodQueue()
	for {
		pod, quit := queue.Get()
		if quit {
			return
		}
		DeleteMetricsForPod(pod.(*corev1.Pod))
		queue.Done(pod)
	}
}
