// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package ringbufqueuemetrics

import (
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	Received = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "ringbuf_queue_received_total",
		Help:        "The total number of Tetragon events ring buffer queue received.",
		ConstLabels: nil,
	})
	Lost = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "ringbuf_queue_lost_total",
		Help:        "The total number of Tetragon events ring buffer queue lost.",
		ConstLabels: nil,
	})
)

func RegisterMetrics(group metrics.Group) {
	group.MustRegister(Received)
	group.MustRegister(Lost)
}
