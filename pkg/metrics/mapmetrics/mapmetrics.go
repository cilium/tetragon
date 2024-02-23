// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package mapmetrics

import (
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	MapDrops = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "map_drops_total",
		Help:        "The total number of entries dropped per LRU map.",
		ConstLabels: nil,
	}, []string{"map"})
	MapSize = metrics.NewBPFGauge(prometheus.NewDesc(
		prometheus.BuildFQName(consts.MetricsNamespace, "", "map_in_use_gauge"),
		"The total number of in-use entries per map.",
		[]string{"map", "total"}, nil,
	))
	MapErrors = metrics.NewBPFCounter(prometheus.NewDesc(
		prometheus.BuildFQName(consts.MetricsNamespace, "", "map_errors_total"),
		"The total number of entries dropped per LRU map.",
		[]string{"map"}, nil,
	))
)

func registerMetrics(registry *prometheus.Registry) {
	registry.MustRegister(MapDrops)
	// custom collectors are registered independently
}

func InitMetrics(registry *prometheus.Registry) {
	registerMetrics(registry)

	// NOTES:
	// * Delete (move/replace) map_drops_total as it's monitoring process cache not maps
	// * Rename map_in_use_gauge metric (to e.g. map_entries) and delete total label?
	// * Introduce a metric for map capacity
}

func MapDropInc(mapName string) {
	MapDrops.WithLabelValues(mapName).Inc()
}

// bpfCollector implements prometheus.Collector. It collects metrics directly from BPF maps.
// NB: We can't register individual BPF collectors collecting map metrics, because they share the
// metrics descriptors. Sending duplicate descriptors from different collectors results in
// a panic. Sending duplicate descriptors from the same collector is fine, so we define a simple
// wrapper for all collectors collecting map metrics.
type bpfCollector struct {
	collectors []prometheus.Collector
}

func NewBPFCollector(collectors ...prometheus.Collector) prometheus.Collector {
	return &bpfCollector{
		collectors: collectors,
	}
}

func (c *bpfCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, m := range c.collectors {
		m.Describe(ch)
	}
}

func (c *bpfCollector) Collect(ch chan<- prometheus.Metric) {
	for _, m := range c.collectors {
		m.Collect(ch)
	}
}
