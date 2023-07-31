// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package opcodemetrics

import (
	"fmt"

	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	MsgOpsCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "msg_op_total",
		Help:        "The total number of times we encounter a given message opcode. For internal use only.",
		ConstLabels: nil,
	}, []string{"msg_op"})

	LatencyStats = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "handling_latency",
		Help:        "The latency of handling messages in us.",
		Buckets:     []float64{50, 100, 500, 1000, 10000, 100000}, // 50us, 100us, 500us, 1ms, 10ms, 100ms
		ConstLabels: nil,
	}, []string{"op"})
)

func InitMetrics(registry *prometheus.Registry) {
	registry.MustRegister(MsgOpsCount)
	registry.MustRegister(LatencyStats)
}

// Get a new handle on a msgOpsCount metric for an OpCode
func GetOpTotal(op int) prometheus.Counter {
	return MsgOpsCount.WithLabelValues(fmt.Sprint(op))
}

// Increment an msgOpsCount for an OpCode
func OpTotalInc(op int) {
	GetOpTotal(op).Inc()
}
