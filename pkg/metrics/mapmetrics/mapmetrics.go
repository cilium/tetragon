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
