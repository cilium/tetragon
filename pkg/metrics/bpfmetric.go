// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metrics

import "github.com/prometheus/client_golang/prometheus"

// BPFMetric represents a metric read directly from a BPF map.
// It's intended to be used in custom collectors. The interface doesn't provide
// any validation, so it's up to the collector implementer to guarantee the
// metrics consistency.
type BPFMetric interface {
	Desc() *prometheus.Desc
	MustMetric(value float64, labelValues ...string) prometheus.Metric
}

type bpfCounter struct {
	desc *prometheus.Desc
}

func NewBPFCounter(desc *prometheus.Desc) BPFMetric {
	return &bpfCounter{desc: desc}
}

func (c *bpfCounter) Desc() *prometheus.Desc {
	return c.desc
}

func (c *bpfCounter) MustMetric(value float64, labelValues ...string) prometheus.Metric {
	return prometheus.MustNewConstMetric(c.desc, prometheus.CounterValue, value, labelValues...)
}

type bpfGauge struct {
	desc *prometheus.Desc
}

func NewBPFGauge(desc *prometheus.Desc) BPFMetric {
	return &bpfGauge{desc: desc}
}

func (g *bpfGauge) Desc() *prometheus.Desc {
	return g.desc
}

func (g *bpfGauge) MustMetric(value float64, labelValues ...string) prometheus.Metric {
	return prometheus.MustNewConstMetric(g.desc, prometheus.GaugeValue, value, labelValues...)
}
