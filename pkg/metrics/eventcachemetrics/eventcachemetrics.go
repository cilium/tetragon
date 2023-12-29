// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package eventcachemetrics

import (
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	ProcessInfo = "process_info"
	ParentInfo  = "parent_info"
	PodInfo     = "pod_info"
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
	eventCacheErrorsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "event_cache_errors_total",
		Help:        "The total of errors encountered while fetching process exec information from the cache.",
		ConstLabels: nil,
	}, []string{"error"})
	eventCacheRetriesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: consts.MetricsNamespace,
		Name:      "event_cache_retries_total",
		Help:      "The total number of retries for event caching per entry type.",
	}, []string{"entry_type"})
	parentInfoErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "event_cache_parent_info_errors_total",
		Help:        "The total of times we failed to fetch cached parent info for a given event type.",
		ConstLabels: nil,
	}, []string{"event_type"})
)

func InitMetrics(registry *prometheus.Registry) {
	registry.MustRegister(processInfoErrors)
	registry.MustRegister(podInfoErrors)
	registry.MustRegister(EventCacheCount)
	registry.MustRegister(eventCacheErrorsTotal)
	registry.MustRegister(eventCacheRetriesTotal)
	registry.MustRegister(parentInfoErrors)
}

// Get a new handle on an processInfoErrors metric for an eventType
func ProcessInfoError(eventType string) prometheus.Counter {
	return processInfoErrors.WithLabelValues(eventType)
}

// Get a new handle on an processInfoErrors metric for an eventType
func PodInfoError(eventType string) prometheus.Counter {
	return podInfoErrors.WithLabelValues(eventType)
}

// Get a new handle on an processInfoErrors metric for an eventType
func EventCacheError(err string) prometheus.Counter {
	return eventCacheErrorsTotal.WithLabelValues(err)
}

// Get a new handle on the eventCacheRetriesTotal metric for an entryType
func EventCacheRetries(entryType string) prometheus.Counter {
	return eventCacheRetriesTotal.WithLabelValues(entryType)
}

// Get a new handle on an processInfoErrors metric for an eventType
func ParentInfoError(eventType string) prometheus.Counter {
	return parentInfoErrors.WithLabelValues(eventType)
}
