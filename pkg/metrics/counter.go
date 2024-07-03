// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// NewCounterVecWithPod is a wrapper around prometheus.NewCounterVec that also registers the metric
// to be cleaned up when a pod is deleted. It should be used only to register metrics that have
// "pod" and "namespace" labels.
func NewCounterVecWithPod(opts prometheus.CounterOpts, labels []string) *prometheus.CounterVec {
	metric := prometheus.NewCounterVec(opts, labels)
	metricsWithPodMutex.Lock()
	metricsWithPod = append(metricsWithPod, metric.MetricVec)
	metricsWithPodMutex.Unlock()
	return metric
}

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
