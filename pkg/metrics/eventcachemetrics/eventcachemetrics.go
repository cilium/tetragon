// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package eventcachemetrics

import (
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
)

type CacheEntryType int

const (
	ProcessInfo CacheEntryType = iota
	ParentInfo
	PodInfo
)

var cacheEntryTypeLabelValues = map[CacheEntryType]string{
	ProcessInfo: "process_info",
	ParentInfo:  "parent_info",
	PodInfo:     "pod_info",
}

func (t CacheEntryType) String() string {
	return cacheEntryTypeLabelValues[t]
}

type CacheError int

const (
	NilProcessPid CacheError = iota
)

var cacheErrorLabelValues = map[CacheError]string{
	NilProcessPid: "nil_process_pid",
}

func (e CacheError) String() string {
	return cacheErrorLabelValues[e]
}

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
	}, []string{"error", "event_type"})
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

func RegisterMetrics(group metrics.Group) {
	group.MustRegister(processInfoErrors)
	group.MustRegister(podInfoErrors)
	group.MustRegister(EventCacheCount)
	group.MustRegister(eventCacheErrorsTotal)
	group.MustRegister(eventCacheRetriesTotal)
	group.MustRegister(parentInfoErrors)
}

func InitMetrics() {
	// Initialize metrics with labels
	for en := range cacheEntryTypeLabelValues {
		EventCacheRetries(en).Add(0)
	}
	for ev := range tetragon.EventType_name {
		if tetragon.EventType(ev) != tetragon.EventType_UNDEF && tetragon.EventType(ev) != tetragon.EventType_TEST {
			ProcessInfoError(tetragon.EventType(ev)).Add(0)
			PodInfoError(tetragon.EventType(ev)).Add(0)
			ParentInfoError(tetragon.EventType(ev)).Add(0)
			for er := range cacheErrorLabelValues {
				EventCacheError(er, tetragon.EventType(ev)).Add(0)
			}
		}
	}
}

// Get a new handle on a processInfoErrors metric for an eventType
func ProcessInfoError(eventType tetragon.EventType) prometheus.Counter {
	return processInfoErrors.WithLabelValues(eventType.String())
}

// Get a new handle on a podInfoErrors metric for an eventType
func PodInfoError(eventType tetragon.EventType) prometheus.Counter {
	return podInfoErrors.WithLabelValues(eventType.String())
}

// Get a new handle on an eventCacheErrorsTotal metric for an error
func EventCacheError(er CacheError, eventType tetragon.EventType) prometheus.Counter {
	return eventCacheErrorsTotal.WithLabelValues(er.String(), eventType.String())
}

// Get a new handle on an eventCacheRetriesTotal metric for an entryType
func EventCacheRetries(entryType CacheEntryType) prometheus.Counter {
	return eventCacheRetriesTotal.WithLabelValues(entryType.String())
}

// Get a new handle on an processInfoErrors metric for an eventType
func ParentInfoError(eventType tetragon.EventType) prometheus.Counter {
	return parentInfoErrors.WithLabelValues(eventType.String())
}
