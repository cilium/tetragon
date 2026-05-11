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
	OnPodDelete(handler func(pod *corev1.Pod))
}

var (
	metricsWithPod      []*prometheus.MetricVec
	metricsWithPodMutex sync.RWMutex
	podQueue            workqueue.TypedDelayingInterface[any]
	podQueueOnce        sync.Once
	deleteDelay         = 1 * time.Minute
)

// RegisterPodDeleteHandler registers a handler for deleting metrics associated
// with deleted pods. Without it, Tetragon kept exposing stale metrics for
// deleted pods. This was causing continuous increase in memory usage in
// Tetragon agent as well as in the metrics scraper.
//
// `events` is the typed pod event source provided by `pkg/manager`. Tests can
// pass a hand-rolled fake satisfying the same interface.
func RegisterPodDeleteHandler(events PodEventSource) {
	logger.GetLogger().Info("Registering pod delete handler for metrics")
	events.OnPodDelete(func(pod *corev1.Pod) {
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

func ListMetricsWithPod() []*prometheus.MetricVec {
	// NB: All additions to the list happen when registering metrics, so it's safe to just return
	// the list here.
	return metricsWithPod
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

// NewCounterVecWithPod is a wrapper around prometheus.NewCounterVec that also
// registers the metric to be cleaned up when a pod is deleted.
//
// It should be used only to register metrics that have "pod" and "namespace"
// labels. Using it for metrics without these labels won't break anything, but
// might add an unnecessary overhead.
func NewCounterVecWithPod(opts prometheus.CounterOpts, labels []string) *prometheus.CounterVec {
	metric := prometheus.NewCounterVec(opts, labels)
	metricsWithPodMutex.Lock()
	metricsWithPod = append(metricsWithPod, metric.MetricVec)
	metricsWithPodMutex.Unlock()
	return metric
}

// NewCounterVecWithPodV2 is a wrapper around prometheus.V2.NewCounterVec that also
// registers the metric to be cleaned up when a pod is deleted.
//
// See NewCounterVecWithPod for usage notes.
func NewCounterVecWithPodV2(opts prometheus.CounterVecOpts) *prometheus.CounterVec {
	metric := prometheus.V2.NewCounterVec(opts)
	metricsWithPodMutex.Lock()
	metricsWithPod = append(metricsWithPod, metric.MetricVec)
	metricsWithPodMutex.Unlock()
	return metric
}

// NewGaugeVecWithPod is a wrapper around prometheus.NewGaugeVec that also
// registers the metric to be cleaned up when a pod is deleted.
//
// See NewCounterVecWithPod for usage notes.
func NewGaugeVecWithPod(opts prometheus.GaugeOpts, labels []string) *prometheus.GaugeVec {
	metric := prometheus.NewGaugeVec(opts, labels)
	metricsWithPodMutex.Lock()
	metricsWithPod = append(metricsWithPod, metric.MetricVec)
	metricsWithPodMutex.Unlock()
	return metric
}

// NewGaugeVecWithPodV2 is a wrapper around prometheus.V2.NewGaugeVec that also
// registers the metric to be cleaned up when a pod is deleted.
//
// See NewCounterVecWithPod for usage notes.
func NewGaugeVecWithPodV2(opts prometheus.GaugeVecOpts) *prometheus.GaugeVec {
	metric := prometheus.V2.NewGaugeVec(opts)
	metricsWithPodMutex.Lock()
	metricsWithPod = append(metricsWithPod, metric.MetricVec)
	metricsWithPodMutex.Unlock()
	return metric
}

// NewHistogramVecWithPod is a wrapper around prometheus.NewHistogramVec that also
// registers the metric to be cleaned up when a pod is deleted.
//
// See NewCounterVecWithPod for usage notes.
func NewHistogramVecWithPod(opts prometheus.HistogramOpts, labels []string) *prometheus.HistogramVec {
	metric := prometheus.NewHistogramVec(opts, labels)
	metricsWithPodMutex.Lock()
	metricsWithPod = append(metricsWithPod, metric.MetricVec)
	metricsWithPodMutex.Unlock()
	return metric
}

// NewHistogramVecWithPodV2 is a wrapper around prometheus.V2.NewHistogramVec that also
// registers the metric to be cleaned up when a pod is deleted.
//
// See NewCounterVecWithPod for usage notes.
func NewHistogramVecWithPodV2(opts prometheus.HistogramVecOpts) *prometheus.HistogramVec {
	metric := prometheus.V2.NewHistogramVec(opts)
	metricsWithPodMutex.Lock()
	metricsWithPod = append(metricsWithPod, metric.MetricVec)
	metricsWithPodMutex.Unlock()
	return metric
}
