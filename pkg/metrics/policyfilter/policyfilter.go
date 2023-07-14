// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package policfilter

import (
	"fmt"
	"strings"

	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	PolicyFilterOpMetrics = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace:   metrics.MetricsNamespace,
		Name:        "policyflter_metrics_total",
		Help:        "Policy filter metrics. For internal use only.",
		ConstLabels: nil,
	}, []string{"subsys", "op", "error_type"})
)

func OpInc(subsys, op string, err error) {
	PolicyFilterOpMetrics.WithLabelValues(
		subsys, op,
		strings.ReplaceAll(fmt.Sprintf("%T", errors.Cause(err)), "*", ""),
	).Inc()
}
