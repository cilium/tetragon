// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package eventcachemetrics

import (
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	processInfoErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "event_cache_process_info_errors_total",
		Help:        "The total of times we failed to fetch cached process info for a given event type.",
		ConstLabels: nil,
	}, []string{"event_type"})
	podInfoErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "event_cache_pod_info_errors_total",
		Help:        "The total of times we failed to fetch cached pod info for a given event type.",
		ConstLabels: nil,
	}, []string{"event_type"})
	EventCacheCount = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "event_cache_accesses_total",
		Help:        "The total number of Tetragon event cache accesses. For internal use only.",
		ConstLabels: nil,
	})
)

func InitMetrics(registry *prometheus.Registry) {
	registry.MustRegister(processInfoErrors)
	registry.MustRegister(podInfoErrors)
	registry.MustRegister(EventCacheCount)
}

// Get a new handle on an processInfoErrors metric for an eventType
func ProcessInfoError(eventType string) prometheus.Counter {
	return processInfoErrors.WithLabelValues(eventType)
}

// Get a new handle on an processInfoErrors metric for an eventType
func PodInfoError(eventType string) prometheus.Counter {
	return podInfoErrors.WithLabelValues(eventType)
}
