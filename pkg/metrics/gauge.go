// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// NewGaugeVecWithPod is a wrapper around prometheus.NewGaugeVec that also registers the metric
// to be cleaned up when a pod is deleted. It should be used only to register metrics that have
// "pod" and "namespace" labels.
func NewGaugeVecWithPod(opts prometheus.GaugeOpts, labels []string) *prometheus.GaugeVec {
	metric := prometheus.NewGaugeVec(opts, labels)
	metricsWithPodMutex.Lock()
	metricsWithPod = append(metricsWithPod, metric.MetricVec)
	metricsWithPodMutex.Unlock()
	return metric
}

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
