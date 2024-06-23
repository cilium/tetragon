// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package ringbufmetrics

import (
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	PerfEventReceived = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "ringbuf_perf_event_received_total",
		Help:        "The total number of Tetragon ringbuf perf events received.",
		ConstLabels: nil,
	})
	PerfEventLost = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "ringbuf_perf_event_lost_total",
		Help:        "The total number of Tetragon ringbuf perf events lost.",
		ConstLabels: nil,
	})
	PerfEventErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "ringbuf_perf_event_errors_total",
		Help:        "The total number of errors when reading the Tetragon ringbuf.",
		ConstLabels: nil,
	})
)

func RegisterMetrics(group metrics.Group) {
	group.MustRegister(PerfEventReceived)
	group.MustRegister(PerfEventLost)
	group.MustRegister(PerfEventErrors)
}
