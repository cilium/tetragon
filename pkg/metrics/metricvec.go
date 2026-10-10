// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metrics

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	// metricsWithPod lists the metrics carrying process labels (namespace,
	// workload, pod, binary), whose series are deleted when a pod is deleted
	// (see metricwithpod.go).
	metricsWithPod      []*prometheus.MetricVec
	metricsWithPodMutex sync.RWMutex
)

func ListMetricsWithPod() []*prometheus.MetricVec {
	// NB: All additions to the list happen when registering metrics, so it's safe to just return
	// the list here.
	return metricsWithPod
}

func registerWithPod(vec *prometheus.MetricVec) {
	metricsWithPodMutex.Lock()
	metricsWithPod = append(metricsWithPod, vec)
	metricsWithPodMutex.Unlock()
}

// NewCounterVecWithPod is a wrapper around prometheus.NewCounterVec that also
// registers the metric for series cleanup.
//
// It should be used only to register metrics that have "pod" and "namespace"
// labels. Using it for metrics without these labels won't break anything, but
// might add an unnecessary overhead.
func NewCounterVecWithPod(opts prometheus.CounterOpts, labels []string) *prometheus.CounterVec {
	metric := prometheus.NewCounterVec(opts, labels)
	registerWithPod(metric.MetricVec)
	return metric
}

// NewCounterVecWithPodV2 is the prometheus.V2.NewCounterVec variant of NewCounterVecWithPod.
func NewCounterVecWithPodV2(opts prometheus.CounterVecOpts) *prometheus.CounterVec {
	metric := prometheus.V2.NewCounterVec(opts)
	registerWithPod(metric.MetricVec)
	return metric
}

// NewGaugeVecWithPod is the prometheus.NewGaugeVec variant of NewCounterVecWithPod.
func NewGaugeVecWithPod(opts prometheus.GaugeOpts, labels []string) *prometheus.GaugeVec {
	metric := prometheus.NewGaugeVec(opts, labels)
	registerWithPod(metric.MetricVec)
	return metric
}

// NewGaugeVecWithPodV2 is the prometheus.V2.NewGaugeVec variant of NewCounterVecWithPod.
func NewGaugeVecWithPodV2(opts prometheus.GaugeVecOpts) *prometheus.GaugeVec {
	metric := prometheus.V2.NewGaugeVec(opts)
	registerWithPod(metric.MetricVec)
	return metric
}

// NewHistogramVecWithPod is the prometheus.NewHistogramVec variant of NewCounterVecWithPod.
func NewHistogramVecWithPod(opts prometheus.HistogramOpts, labels []string) *prometheus.HistogramVec {
	metric := prometheus.NewHistogramVec(opts, labels)
	registerWithPod(metric.MetricVec)
	return metric
}

// NewHistogramVecWithPodV2 is the prometheus.V2.NewHistogramVec variant of NewCounterVecWithPod.
func NewHistogramVecWithPodV2(opts prometheus.HistogramVecOpts) *prometheus.HistogramVec {
	metric := prometheus.V2.NewHistogramVec(opts)
	registerWithPod(metric.MetricVec)
	return metric
}
