// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package opcodemetrics

import (
	"fmt"

	"github.com/cilium/tetragon/pkg/api/ops"
	"github.com/cilium/tetragon/pkg/metrics"
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

func RegisterMetrics(group metrics.Group) {
	group.MustRegister(MsgOpsCount)
	group.MustRegister(LatencyStats)
}

func InitMetrics() {
	// Initialize all metrics
	for opcode := range ops.OpCodeStrings {
		if opcode != ops.MsgOpUndef && opcode != ops.MsgOpTest {
			GetOpTotal(opcode).Add(0)
			LatencyStats.WithLabelValues(fmt.Sprint(int32(opcode)))
		}
	}
}

// Get a new handle on a msgOpsCount metric for an OpCode
func GetOpTotal(opcode ops.OpCode) prometheus.Counter {
	return MsgOpsCount.WithLabelValues(fmt.Sprint(int32(opcode)))
}

// Increment an msgOpsCount for an OpCode
func OpTotalInc(opcode ops.OpCode) {
	GetOpTotal(opcode).Inc()
}
