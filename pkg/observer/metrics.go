// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package observer

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
)

const (
	subsystem = "observer"
)

var (
	operationLabel = metrics.ConstrainedLabel{
		Name:   "operation",
		Values: []string{"get", "remove"},
	}
)

var (
	// TODO: These metrics are also stored as Observer struct fields. We could
	// collect them only once: https://github.com/cilium/tetragon/issues/2834

	RingbufReceived = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace:   consts.MetricsNamespace,
		Subsystem:   subsystem,
		Name:        "ringbuf_events_received_total",
		Help:        "Number of perf events Tetragon ring buffer received.",
		ConstLabels: nil,
	})
	RingbufLost = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace:   consts.MetricsNamespace,
		Subsystem:   subsystem,
		Name:        "ringbuf_events_lost_total",
		Help:        "Number of perf events Tetragon ring buffer lost.",
		ConstLabels: nil,
	})
	RingbufErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace:   consts.MetricsNamespace,
		Subsystem:   subsystem,
		Name:        "ringbuf_errors_total",
		Help:        "Number of errors when reading Tetragon ring buffer.",
		ConstLabels: nil,
	})

	queueReceived = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace:   consts.MetricsNamespace,
		Subsystem:   subsystem,
		Name:        "ringbuf_queue_events_received_total",
		Help:        "Number of perf events Tetragon ring buffer events queue received.",
		ConstLabels: nil,
	})
	queueLost = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace:   consts.MetricsNamespace,
		Subsystem:   subsystem,
		Name:        "ringbuf_queue_events_lost_total",
		Help:        "Number of perf events Tetragon ring buffer events queue lost.",
		ConstLabels: nil,
	})

	dataCacheTotal = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "data_cache_size",
		Help:        "The size of the data cache",
		ConstLabels: nil,
	})
	dataCacheCapacity = metrics.MustNewCustomGauge(metrics.NewOpts(
		consts.MetricsNamespace, "", "data_cache_capacity",
		"The capacity of the data cache.",
		nil, nil, nil,
	))
	dataCacheEvictions = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: consts.MetricsNamespace,
		Name:      "data_cache_evictions_total",
		Help:      "Number of data cache LRU evictions.",
	})
	dataCacheMisses = metrics.MustNewCounter(metrics.NewOpts(
		consts.MetricsNamespace, "",
		"data_cache_misses_total",
		"Number of data cache misses.",
		nil,
		[]metrics.ConstrainedLabel{operationLabel},
		nil,
	), nil)
)

func newCacheCollector() prometheus.Collector {
	return metrics.NewCustomCollector(
		metrics.CustomMetrics{dataCacheCapacity},
		func(ch chan<- prometheus.Metric) {
			capacity := 0
			if dataCache != nil {
				capacity = dataCache.size
			}
			ch <- dataCacheCapacity.MustMetric(float64(capacity))
		},
		nil,
	)
}

func RegisterHealthMetrics(group metrics.Group) {
	group.MustRegister(RingbufReceived)
	group.MustRegister(RingbufLost)
	group.MustRegister(RingbufErrors)
	group.MustRegister(queueReceived)
	group.MustRegister(queueLost)
	group.MustRegister(
		dataCacheTotal,
		dataCacheEvictions,
		dataCacheMisses,
		newCacheCollector())
}
