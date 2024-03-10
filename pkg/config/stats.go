// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package config

import (
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	stats = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "config_stats_total",
		Help:        "Config statistics. For internal use only.",
		ConstLabels: nil,
	}, []string{"count"})
)

func InitMetrics(registry *prometheus.Registry) {
	registry.MustRegister(stats)

	// Initialize metrics with labels
	for _, ty := range StatsStrings {
		stats.WithLabelValues(ty).Add(0)
	}
}

type StatsType int

const (
	ParseOk StatsType = iota
	ParseFail
	Reload
)

var StatsStrings = map[StatsType]string{
	ParseOk:   "ParseOk",
	ParseFail: "ParseFail",
	Reload:    "Reload",
}

func MetricInc(ty StatsType) {
	stats.WithLabelValues(StatsStrings[ty]).Inc()
}
