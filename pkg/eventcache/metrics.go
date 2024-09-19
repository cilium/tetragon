// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package eventcache

import (
	"maps"
	"slices"

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
	AncestorsInfo
	PodInfo
)

var cacheEntryTypeLabelValues = map[CacheEntryType]string{
	ProcessInfo:   "process_info",
	ParentInfo:    "parent_info",
	AncestorsInfo: "ancestors_info",
	PodInfo:       "pod_info",
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
		Values: slices.Collect(maps.Values(cacheEntryTypeLabelValues)),
	}
	errorLabel = metrics.ConstrainedLabel{
		Name:   "error",
		Values: slices.Collect(maps.Values(cacheErrorLabelValues)),
	}
)

var (
	cacheErrors = metrics.MustNewCounter(metrics.NewOpts(
		consts.MetricsNamespace, subsystem, "errors_total",
		"The total of errors encountered while fetching process exec information from the cache.",
		nil, []metrics.ConstrainedLabel{errorLabel, metrics.EventTypeLabel}, nil,
	), nil)
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
	cacheRetries = metrics.MustNewCounter(metrics.NewOpts(
		consts.MetricsNamespace, subsystem, "fetch_retries_total",
		"Number of retries when fetching info from the event cache.",
		nil, []metrics.ConstrainedLabel{entryTypeLabel}, nil,
	), nil)
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
	group.MustRegister(
		newCacheCollector(),
		cacheErrors,
		cacheInserts,
		cacheRetries,
		failedFetches,
	)
}

// Get a new handle on an eventCacheErrorsTotal metric for an error
func CacheErrors(er CacheError, eventType tetragon.EventType) prometheus.Counter {
	return cacheErrors.WithLabelValues(er.String(), eventType.String())
}

// Get a new handle on an eventCacheRetriesTotal metric for an entryType
func CacheRetries(entryType CacheEntryType) prometheus.Counter {
	return cacheRetries.WithLabelValues(entryType.String())
}
