// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// The interface in this file provides a bridge between the new metrics library
// and the existing code defining metrics. It's considered deprecated - use the
// custom metric interface instead.

type BPFMetric interface {
	Desc() *prometheus.Desc
	MustMetric(value float64, labelValues ...string) prometheus.Metric
}

type bpfCounter struct {
	*granularCustomCounter[NilLabels]
}

// DEPRECATED: Use NewCustomCounter instead.
func NewBPFCounter(desc *prometheus.Desc) BPFMetric {
	return &bpfCounter{
		&granularCustomCounter[NilLabels]{
			desc:        desc,
			constrained: false,
		},
	}
}

func (m *bpfCounter) Desc() *prometheus.Desc {
	return m.granularCustomCounter.Desc()
}

func (m *bpfCounter) MustMetric(value float64, labelValues ...string) prometheus.Metric {
	return m.granularCustomCounter.MustMetric(value, &NilLabels{}, labelValues...)
}

type bpfGauge struct {
	*granularCustomGauge[NilLabels]
}

// DEPRECATED: Use NewCustomGauge instead.
func NewBPFGauge(desc *prometheus.Desc) BPFMetric {
	return &bpfGauge{
		&granularCustomGauge[NilLabels]{
			desc:        desc,
			constrained: false,
		},
	}
}

func (m *bpfGauge) Desc() *prometheus.Desc {
	return m.granularCustomGauge.Desc()
}

func (m *bpfGauge) MustMetric(value float64, labelValues ...string) prometheus.Metric {
	return m.granularCustomGauge.MustMetric(value, &NilLabels{}, labelValues...)
}
