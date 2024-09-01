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
	LatencyStats = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "handling_latency",
		Help:        "The latency of handling messages in us.",
		Buckets:     []float64{50, 100, 500, 1000, 10000, 100000}, // 50us, 100us, 500us, 1ms, 10ms, 100ms
		ConstLabels: nil,
	}, []string{"op"})
)

func RegisterMetrics(group metrics.Group) {
	group.MustRegister(LatencyStats)
}

func InitMetrics() {
	// Initialize all metrics
	for opcode := range ops.OpCodeStrings {
		if opcode != ops.MSG_OP_UNDEF && opcode != ops.MSG_OP_TEST {
			LatencyStats.WithLabelValues(fmt.Sprint(int32(opcode)))
		}
	}
}
