// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package observer

import (
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	// TODO: These metrics are also stored as Observer struct fields. We could
	// collect them only once: https://github.com/cilium/tetragon/issues/2834

	RingbufReceived = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "ringbuf_perf_event_received_total",
		Help:        "The total number of Tetragon ringbuf perf events received.",
		ConstLabels: nil,
	})
	RingbufLost = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "ringbuf_perf_event_lost_total",
		Help:        "The total number of Tetragon ringbuf perf events lost.",
		ConstLabels: nil,
	})
	RingbufErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "ringbuf_perf_event_errors_total",
		Help:        "The total number of errors when reading the Tetragon ringbuf.",
		ConstLabels: nil,
	})

	queueReceived = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "ringbuf_queue_received_total",
		Help:        "The total number of Tetragon events ring buffer queue received.",
		ConstLabels: nil,
	})
	queueLost = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "ringbuf_queue_lost_total",
		Help:        "The total number of Tetragon events ring buffer queue lost.",
		ConstLabels: nil,
	})
)

func RegisterHealthMetrics(group metrics.Group) {
	group.MustRegister(RingbufReceived)
	group.MustRegister(RingbufLost)
	group.MustRegister(RingbufErrors)
	group.MustRegister(queueReceived)
	group.MustRegister(queueLost)
}
