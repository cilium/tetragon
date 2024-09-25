// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package process

import (
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	operationLabel = metrics.ConstrainedLabel{
		Name:   "operation",
		Values: []string{"get", "remove"},
	}
)

var (
	processCacheTotal = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "process_cache_size",
		Help:        "The size of the process cache",
		ConstLabels: nil,
	})
	processCacheCapacity = metrics.MustNewCustomGauge(metrics.NewOpts(
		consts.MetricsNamespace, "", "process_cache_capacity",
		"The capacity of the process cache. Expected to be constant.",
		nil, nil, nil,
	))
	processCacheEvictions = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: consts.MetricsNamespace,
		Name:      "process_cache_evictions_total",
		Help:      "Number of process cache LRU evictions.",
	})
	processCacheMisses = metrics.MustNewCounter(metrics.NewOpts(
		consts.MetricsNamespace, "", "process_cache_misses_total",
		"Number of process cache misses.",
		nil, []metrics.ConstrainedLabel{operationLabel}, nil,
	), nil)
	processCacheRemovedStale = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: consts.MetricsNamespace,
		Name:      "process_cache_removed_stale_total",
		Help:      "Number of process cache stale entries removed.",
	})
)

func newCacheCollector() prometheus.Collector {
	return metrics.NewCustomCollector(
		metrics.CustomMetrics{processCacheCapacity},
		func(ch chan<- prometheus.Metric) {
			capacity := 0
			if procCache != nil {
				capacity = procCache.size
			}
			ch <- processCacheCapacity.MustMetric(float64(capacity))
		},
		nil,
	)
}

func RegisterMetrics(group metrics.Group) {
	group.MustRegister(
		processCacheTotal,
		processCacheEvictions,
		processCacheMisses,
		processCacheRemovedStale,
	)
	group.MustRegister(newCacheCollector())
}
