// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package policyfiltermetrics

import (
	"fmt"
	"strings"

	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	PolicyFilterOpMetrics = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "policyfilter_metrics_total",
		Help:        "Policy filter metrics. For internal use only.",
		ConstLabels: nil,
	}, []string{"subsys", "op", "error_type"})
)

func registerMetrics(registry *prometheus.Registry) {
	registry.MustRegister(PolicyFilterOpMetrics)
}

func InitMetrics(registry *prometheus.Registry) {
	registerMetrics(registry)

	// NOTES:
	// * error, error_type, type - standardize on a label
	// * Don't confuse op and opcode labels
	// * Rename policyfilter_metrics_total to get rid of _metrics?
}

func OpInc(subsys, op string, err error) {
	PolicyFilterOpMetrics.WithLabelValues(
		subsys, op,
		strings.ReplaceAll(fmt.Sprintf("%T", errors.Cause(err)), "*", ""),
	).Inc()
}
