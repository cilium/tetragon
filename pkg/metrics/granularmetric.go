// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metrics

import (
	"fmt"
	"slices"

	"github.com/prometheus/client_golang/prometheus"
)

func validateExtraLabels(common []string, extra []string) error {
	for _, label := range extra {
		if slices.Contains(common, label) {
			return fmt.Errorf("extra labels can't contain any of the following: %v", common)
		}
	}
	return nil
}

// counter

type GranularCounter[L FilteredLabels] struct {
	metric *prometheus.CounterVec
}

func NewGranularCounter[L FilteredLabels](opts prometheus.CounterOpts, extraLabels []string) (*GranularCounter[L], error) {
	var dummy L
	commonLabels := dummy.Keys()
	err := validateExtraLabels(commonLabels, extraLabels)
	if err != nil {
		return nil, err
	}
	return &GranularCounter[L]{
		// NB: Using the WithPod wrapper means an implicit assumption that the metric has "pod" and
		// "namespace" labels, and will be cleaned up on pod deletion. If this is not the case, the
		// metric will still work, just the unnecessary cleanup logic will add some overhead.
		metric: NewCounterVecWithPod(opts, append(commonLabels, extraLabels...)),
	}, nil
}

func MustNewGranularCounter[L FilteredLabels](opts prometheus.CounterOpts, extraLabels []string) *GranularCounter[L] {
	result, err := NewGranularCounter[L](opts, extraLabels)
	if err != nil {
		panic(err)
	}
	return result
}

func (m *GranularCounter[L]) Describe(ch chan<- *prometheus.Desc) {
	m.metric.Describe(ch)
}

func (m *GranularCounter[L]) Collect(ch chan<- prometheus.Metric) {
	m.metric.Collect(ch)
}

func (m *GranularCounter[L]) WithLabelValues(commonLvs *L, extraLvs ...string) prometheus.Counter {
	lvs := append((*commonLvs).Values(), extraLvs...)
	return m.metric.WithLabelValues(lvs...)
}

// gauge

type GranularGauge[L FilteredLabels] struct {
	metric *prometheus.GaugeVec
}

func NewGranularGauge[L FilteredLabels](opts prometheus.GaugeOpts, extraLabels []string) (*GranularGauge[L], error) {
	var dummy L
	commonLabels := dummy.Keys()
	err := validateExtraLabels(commonLabels, extraLabels)
	if err != nil {
		return nil, err
	}
	return &GranularGauge[L]{
		// NB: Using the WithPod wrapper means an implicit assumption that the metric has "pod" and
		// "namespace" labels, and will be cleaned up on pod deletion. If this is not the case, the
		// metric will still work, just the unnecessary cleanup logic will add some overhead.
		metric: NewGaugeVecWithPod(opts, append(commonLabels, extraLabels...)),
	}, nil
}

func MustNewGranularGauge[L FilteredLabels](opts prometheus.GaugeOpts, extraLabels []string) *GranularGauge[L] {
	result, err := NewGranularGauge[L](opts, extraLabels)
	if err != nil {
		panic(err)
	}
	return result
}

func (m *GranularGauge[L]) Describe(ch chan<- *prometheus.Desc) {
	m.metric.Describe(ch)
}

func (m *GranularGauge[L]) Collect(ch chan<- prometheus.Metric) {
	m.metric.Collect(ch)
}

func (m *GranularGauge[L]) WithLabelValues(commonLvs *L, extraLvs ...string) prometheus.Gauge {
	lvs := append((*commonLvs).Values(), extraLvs...)
	return m.metric.WithLabelValues(lvs...)
}

// histogram

type GranularHistogram[L FilteredLabels] struct {
	metric *prometheus.HistogramVec
}

func NewGranularHistogram[L FilteredLabels](opts prometheus.HistogramOpts, extraLabels []string) (*GranularHistogram[L], error) {
	var dummy L
	commonLabels := dummy.Keys()
	err := validateExtraLabels(commonLabels, extraLabels)
	if err != nil {
		return nil, err
	}
	return &GranularHistogram[L]{
		// NB: Using the WithPod wrapper means an implicit assumption that the metric has "pod" and
		// "namespace" labels, and will be cleaned up on pod deletion. If this is not the case, the
		// metric will still work, just the unnecessary cleanup logic will add some overhead.
		metric: NewHistogramVecWithPod(opts, append(commonLabels, extraLabels...)),
	}, nil
}

func MustNewGranularHistogram[L FilteredLabels](opts prometheus.HistogramOpts, extraLabels []string) *GranularHistogram[L] {
	result, err := NewGranularHistogram[L](opts, extraLabels)
	if err != nil {
		panic(err)
	}
	return result
}

func (m *GranularHistogram[L]) Describe(ch chan<- *prometheus.Desc) {
	m.metric.Describe(ch)
}

func (m *GranularHistogram[L]) Collect(ch chan<- prometheus.Metric) {
	m.metric.Collect(ch)
}

func (m *GranularHistogram[L]) WithLabelValues(commonLvs *L, extraLvs ...string) prometheus.Observer {
	lvs := append((*commonLvs).Values(), extraLvs...)
	return m.metric.WithLabelValues(lvs...)
}
