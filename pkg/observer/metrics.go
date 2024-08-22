// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package observer

import (
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	subsystem = "observer"
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
)

func RegisterHealthMetrics(group metrics.Group) {
	group.MustRegister(RingbufReceived)
	group.MustRegister(RingbufLost)
	group.MustRegister(RingbufErrors)
	group.MustRegister(queueReceived)
	group.MustRegister(queueLost)
}
