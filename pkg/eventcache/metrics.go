// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package eventcache

import (
	"golang.org/x/exp/maps"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	subsystem = "event_cache"
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
	entryTypeLabel = metrics.ConstrainedLabel{
		Name:   "entry_type",
		Values: maps.Values(cacheEntryTypeLabelValues),
	}
)

var (
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
	cacheSize = metrics.MustNewCustomGauge(metrics.NewOpts(
		consts.MetricsNamespace, "", "event_cache_entries",
		"The number of entries in the event cache.",
		nil, nil, nil,
	))
	cacheInserts = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace:   consts.MetricsNamespace,
		Subsystem:   subsystem,
		Name:        "inserts_total",
		Help:        "Number of inserts to the event cache.",
		ConstLabels: nil,
	})
	failedFetches = metrics.MustNewCounter(metrics.NewOpts(
		consts.MetricsNamespace, subsystem, "fetch_failures_total",
		"Number of failed fetches from the event cache. These won't be retried as they already exceeded the limit.",
		nil, []metrics.ConstrainedLabel{metrics.EventTypeLabel, entryTypeLabel}, nil,
	), nil)
)

func newCacheCollector() prometheus.Collector {
	return metrics.NewCustomCollector(
		metrics.CustomMetrics{cacheSize},
		func(ch chan<- prometheus.Metric) {
			size := 0
			if cache != nil {
				size = cache.len()
			}
			ch <- cacheSize.MustMetric(float64(size))
		},
		nil,
	)
}

func RegisterMetrics(group metrics.Group) {
	group.MustRegister(eventCacheErrorsTotal)
	group.MustRegister(eventCacheRetriesTotal)
	group.MustRegister(
		newCacheCollector(),
		cacheInserts,
		failedFetches,
	)
}

func InitMetrics() {
	// Initialize metrics with labels
	for en := range cacheEntryTypeLabelValues {
		EventCacheRetries(en).Add(0)
	}
	for ev := range tetragon.EventType_name {
		if tetragon.EventType(ev) != tetragon.EventType_UNDEF && tetragon.EventType(ev) != tetragon.EventType_TEST {
			for er := range cacheErrorLabelValues {
				EventCacheError(er, tetragon.EventType(ev)).Add(0)
			}
		}
	}
}

// Get a new handle on an eventCacheErrorsTotal metric for an error
func EventCacheError(er CacheError, eventType tetragon.EventType) prometheus.Counter {
	return eventCacheErrorsTotal.WithLabelValues(er.String(), eventType.String())
}

// Get a new handle on an eventCacheRetriesTotal metric for an entryType
func EventCacheRetries(entryType CacheEntryType) prometheus.Counter {
	return eventCacheRetriesTotal.WithLabelValues(entryType.String())
}
