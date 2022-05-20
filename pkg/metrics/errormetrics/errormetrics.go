// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package errormetrics

import (
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type ErrorType string

var (
	// Parent process was not found in the pid map for a process without the clone flag.
	NoParentNoClone ErrorType = "no_parent_no_clone"
	// Process not found on get() call.
	ProcessCacheMissOnGet ErrorType = "process_cache_miss_on_get"
	// Process evicted from the cache.
	ProcessCacheEvicted ErrorType = "process_cache_evicted"
	// Process not found on remove() call.
	ProcessCacheMissOnRemove ErrorType = "process_cache_miss_on_remove"
	// Missing event handler.
	UnhandledEvent ErrorType = "unhandled_event"
	// Event cache add network entry to cache.
	EventCacheNetworkCount ErrorType = "event_cache_network_count"
	// Event cache add process entry to cache.
	EventCacheProcessCount ErrorType = "event_cache_process_count"
	// Event cache podInfo retries failed.
	EventCachePodInfoRetryFailed ErrorType = "event_cache_podinfo_retry_failed"
	// Event cache endpoint retries failed.
	EventCacheEndpointRetryFailed ErrorType = "event_cache_endpoint_retry_failed"
	// Event cache failed to set process information for an event.
	EventCacheProcessInfoFailed ErrorType = "event_cache_process_info_failed"
	// There was an invalid entry in the pid map.
	PidMapInvalidEntry ErrorType = "pid_map_invalid_entry"
	// An entry was evicted from the pid map because the map was full.
	PidMapEvicted ErrorType = "pid_map_evicted"
	// PID not found in the pid map on remove() call.
	PidMapMissOnRemove ErrorType = "pid_map_miss_on_remove"
	// An exec event without parent info.
	ExecMissingParent ErrorType = "exec_missing_parent"
)

// Get a new handle on an errorsTotal metric for an ErrorType
func ErrorTotal(t ErrorType) prometheus.Counter {
	return errorsTotal.WithLabelValues(string(t))
}

// Increment an errorsTotal for an ErrorType
func ErrorTotalInc(t ErrorType) {
	ErrorTotal(t).Inc()
}

// Get a new handle on an eventCacheCount metric for an ErrorType
func EventCache(t ErrorType) prometheus.Counter {
	return eventCacheCount.WithLabelValues(string(t))
}

// Increment an eventCacheCount for an ErrorType
func EventCacheInc(t ErrorType) {
	ErrorTotal(t).Inc()
}

var (
	errorsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:        consts.MetricNamePrefix + "errors_total",
		Help:        "The total number of Tetragon errors. For internal use only.",
		ConstLabels: nil,
	}, []string{"type"})
	eventCacheCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:        consts.MetricNamePrefix + "event_cache",
		Help:        "The total number of Tetragon event cache access/errors. For internal use only.",
		ConstLabels: nil,
	}, []string{"type"})
)
