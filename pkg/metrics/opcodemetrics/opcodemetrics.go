// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package opcodemetrics

import (
	"github.com/cilium/tetragon/pkg/api/ops"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	msgOpsCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:        consts.MetricNamePrefix + "msg_op_total",
		Help:        "The total number of times we encounter a given message opcode. For internal use only.",
		ConstLabels: nil,
	}, []string{"msg_op"})
)

// Get a new handle on a msgOpsCount metric for an OpCode
func OpTotal(op ops.OpCode) prometheus.Counter {
	return msgOpsCount.WithLabelValues(op.String())
}

// Increment an msgOpsCount for an OpCode
func OpTotalInc(op ops.OpCode) {
	OpTotal(op).Inc()
}
