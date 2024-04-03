// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package mapmetrics

import (
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	MapSize = metrics.NewBPFGauge(prometheus.NewDesc(
		prometheus.BuildFQName(consts.MetricsNamespace, "", "map_entries"),
		"The total number of in-use entries per map.",
		[]string{"map"}, nil,
	))
	MapCapacity = metrics.NewBPFGauge(prometheus.NewDesc(
		prometheus.BuildFQName(consts.MetricsNamespace, "", "map_capacity"),
		"Capacity of a BPF map. Expected to be constant.",
		[]string{"map"}, nil,
	))
	MapErrors = metrics.NewBPFCounter(prometheus.NewDesc(
		prometheus.BuildFQName(consts.MetricsNamespace, "", "map_errors_total"),
		"The number of errors per map.",
		[]string{"map"}, nil,
	))
)

func InitMetrics(_ *prometheus.Registry) {
	// custom collectors are registered independently
}
