// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package opcodemetrics

import (
	"strconv"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/tetragon/pkg/api/ops"
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
)

var (
	MsgOpsCount = metrics.MustNewCounter(
		metrics.NewOpts(
			consts.MetricsNamespace, "", "msg_op_total",
			"The total number of times we encounter a given message opcode. For internal use only.",
			nil, []metrics.ConstrainedLabel{{Name: "msg_op", Values: func() []string {
				res := make([]string, 0, len(ops.OpCodeStrings))
				for opcode := range ops.OpCodeStrings {
					// Exclude MSG_OP_UNDEF (0) as it's not a valid operational opcode - only used for error tracking.
					// Also exclude MSG_OP_TEST as it's only used for testing purposes.
					if opcode != ops.MSG_OP_UNDEF && opcode != ops.MSG_OP_TEST {
						res = append(res, strconv.Itoa(int(int32(opcode))))
					}
				}
				return res
			}()}}, nil,
		),
		nil,
	)

	LatencyStats = metrics.MustNewHistogram(
		metrics.HistogramOpts{
			Opts: metrics.NewOpts(
				consts.MetricsNamespace, "", "handling_latency",
				"The latency of handling messages in us.",
				nil, []metrics.ConstrainedLabel{{Name: "op", Values: func() []string {
					res := make([]string, 0, len(ops.OpCodeStrings))
					for opcode := range ops.OpCodeStrings {
						if opcode != ops.MSG_OP_UNDEF && opcode != ops.MSG_OP_TEST {
							res = append(res, strconv.Itoa(int(int32(opcode))))
						}
					}
					return res
				}()}}, nil,
			),
			Buckets: []float64{50, 100, 500, 1000, 10000, 100000}, // 50us, 100us, 500us, 1ms, 10ms, 100ms
		},
		nil,
	)
)

func RegisterMetrics(group metrics.Group) {
	group.MustRegister(MsgOpsCount)
	group.MustRegister(LatencyStats)
}

func InitMetrics() {
	// Initialize all metrics
	for opcode := range ops.OpCodeStrings {
		if opcode != ops.MSG_OP_UNDEF && opcode != ops.MSG_OP_TEST {
			GetOpTotal(opcode).Add(0)
			LatencyStats.WithLabelValues(strconv.Itoa(int(int32(opcode))))
		}
	}
}

// Get a new handle on a msgOpsCount metric for an OpCode
func GetOpTotal(opcode ops.OpCode) prometheus.Counter {
	return MsgOpsCount.WithLabelValues(strconv.Itoa(int(int32(opcode))))
}

// Increment an msgOpsCount for an OpCode
func OpTotalInc(opcode ops.OpCode) {
	GetOpTotal(opcode).Inc()
}
