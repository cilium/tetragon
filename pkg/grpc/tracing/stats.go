// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"maps"
	"slices"

	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
)

var (
	LoaderStats = metrics.MustNewCounter(
		metrics.NewOpts(
			consts.MetricsNamespace, "", "process_loader_stats",
			"Process Loader event statistics. For internal use only.",
			nil, []metrics.ConstrainedLabel{{Name: "count", Values: slices.Collect(maps.Values(LoaderTypeStrings))}}, nil,
		),
		nil,
	)
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
