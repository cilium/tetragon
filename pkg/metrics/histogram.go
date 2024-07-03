// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// NewHistogramVecWithPod is a wrapper around prometheus.NewHistogramVec that also registers the metric
// to be cleaned up when a pod is deleted. It should be used only to register metrics that have
// "pod" and "namespace" labels.
func NewHistogramVecWithPod(opts prometheus.HistogramOpts, labels []string) *prometheus.HistogramVec {
	metric := prometheus.NewHistogramVec(opts, labels)
	metricsWithPodMutex.Lock()
	metricsWithPod = append(metricsWithPod, metric.MetricVec)
	metricsWithPodMutex.Unlock()
	return metric
}

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
