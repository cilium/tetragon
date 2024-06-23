// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	LoaderStats = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "process_loader_stats",
		Help:        "Process Loader event statistics. For internal use only.",
		ConstLabels: nil,
	}, []string{"count"})
)

func RegisterMetrics(group metrics.Group) {
	group.MustRegister(LoaderStats)
}

func InitMetrics() {
	// Initialize metrics with labels
	for _, ty := range LoaderTypeStrings {
		LoaderStats.WithLabelValues(ty).Add(0)
	}
}

type LoaderType int

const (
	LoaderReceived LoaderType = iota
	LoaderResolvedImm
	LoaderResolvedRetry
)

var LoaderTypeStrings = map[LoaderType]string{
	LoaderReceived:      "LoaderReceived",
	LoaderResolvedImm:   "LoaderResolvedImm",
	LoaderResolvedRetry: "LoaderResolvedRetry",
}

// Increment a Build Id metric for a retrieval type
func LoaderMetricInc(ty LoaderType) {
	LoaderStats.WithLabelValues(LoaderTypeStrings[ty]).Inc()
}
