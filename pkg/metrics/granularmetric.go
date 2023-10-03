// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metrics

import (
	"fmt"
	"sync"

	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/exp/slices"
)

var (
	granularLabelFilter = NewLabelFilter(
		consts.KnownMetricLabelFilters,
		option.Config.MetricsLabelFilter,
	)
)

type LabelFilter struct {
	known   []string
	enabled map[string]interface{}
}

func NewLabelFilter(known []string, enabled map[string]interface{}) *LabelFilter {
	return &LabelFilter{
		known:   known,
		enabled: enabled,
	}
}

// metric

type granularMetricIface interface {
	filter(labels ...string) ([]string, error)
	mustFilter(labels ...string) []string
}

type granularMetric struct {
	labels      []string
	labelFilter *LabelFilter
	eval        sync.Once
}

func newGranularMetric(f *LabelFilter, labels []string) (*granularMetric, error) {
	for _, label := range labels {
		if slices.Contains(f.known, label) {
			return nil, fmt.Errorf("passed labels can't contain any of the following: %v", f.known)
		}
	}
	return &granularMetric{
		labels:      append(labels, f.known...),
		labelFilter: f,
	}, nil
}

// filter takes in string arguments and returns a slice of those strings omitting the labels not configured in the metric labelFilter.
// IMPORTANT! The filtered metric labels must be passed last and in the exact order of granularMetric.labelFilter.known.
func (m *granularMetric) filter(labels ...string) ([]string, error) {
	offset := len(labels) - len(m.labelFilter.known)
	if offset < 0 {
		return nil, fmt.Errorf("not enough labels provided to filter")
	}
	result := labels[:offset]
	for i, label := range m.labelFilter.known {
		if _, ok := m.labelFilter.enabled[label]; ok {
			result = append(result, labels[offset+i])
		}
	}
	return result, nil
}

func (m *granularMetric) mustFilter(labels ...string) []string {
	result, err := m.filter(labels...)
	if err != nil {
		panic(err)
	}
	return result
}

// counter

type GranularCounter interface {
	granularMetricIface
	ToProm() *prometheus.CounterVec
	WithLabelValues(lvs ...string) prometheus.Counter
}

type granularCounter struct {
	*granularMetric
	metric *prometheus.CounterVec
	opts   prometheus.CounterOpts
}

func NewGranularCounter(f *LabelFilter, opts prometheus.CounterOpts, labels []string) (GranularCounter, error) {
	metric, err := newGranularMetric(f, labels)
	if err != nil {
		return nil, err
	}
	return &granularCounter{
		granularMetric: metric,
		opts:           opts,
	}, nil
}

func MustNewGranularCounter(opts prometheus.CounterOpts, labels []string) GranularCounter {
	counter, err := NewGranularCounter(granularLabelFilter, opts, labels)
	if err != nil {
		panic(err)
	}
	return counter
}

func (m *granularCounter) ToProm() *prometheus.CounterVec {
	m.eval.Do(func() {
		m.labels = m.mustFilter(m.labels...)
		m.metric = NewCounterVecWithPod(m.opts, m.labels)
	})
	return m.metric
}

func (m *granularCounter) WithLabelValues(lvs ...string) prometheus.Counter {
	filtered := m.mustFilter(lvs...)
	return m.ToProm().WithLabelValues(filtered...)
}

// gauge

type GranularGauge interface {
	granularMetricIface
	ToProm() *prometheus.GaugeVec
	WithLabelValues(lvs ...string) prometheus.Gauge
}

type granularGauge struct {
	*granularMetric
	metric *prometheus.GaugeVec
	opts   prometheus.GaugeOpts
}

func NewGranularGauge(f *LabelFilter, opts prometheus.GaugeOpts, labels []string) (GranularGauge, error) {
	for _, label := range labels {
		if slices.Contains(f.known, label) {
			return nil, fmt.Errorf("passed labels can't contain any of the following: %v", f.known)
		}
	}
	return &granularGauge{
		granularMetric: &granularMetric{
			labels: append(labels, f.known...),
		},
		opts: opts,
	}, nil
}

func MustNewGranularGauge(opts prometheus.GaugeOpts, labels []string) GranularGauge {
	result, err := NewGranularGauge(granularLabelFilter, opts, labels)
	if err != nil {
		panic(err)
	}
	return result
}

func (m *granularGauge) ToProm() *prometheus.GaugeVec {
	m.eval.Do(func() {
		m.labels = m.mustFilter(m.labels...)
		m.metric = NewGaugeVecWithPod(m.opts, m.labels)
	})
	return m.metric
}

func (m *granularGauge) WithLabelValues(lvs ...string) prometheus.Gauge {
	filtered := m.mustFilter(lvs...)
	return m.ToProm().WithLabelValues(filtered...)
}

// histogram

type GranularHistogram interface {
	granularMetricIface
	ToProm() *prometheus.HistogramVec
	WithLabelValues(lvs ...string) prometheus.Observer
}

type granularHistogram struct {
	*granularMetric
	metric *prometheus.HistogramVec
	opts   prometheus.HistogramOpts
}

func NewGranularHistogram(f *LabelFilter, opts prometheus.HistogramOpts, labels []string) (GranularHistogram, error) {
	for _, label := range labels {
		if slices.Contains(f.known, label) {
			return nil, fmt.Errorf("passed labels can't contain any of the following: %v", f.known)
		}
	}
	return &granularHistogram{
		granularMetric: &granularMetric{
			labels: append(labels, f.known...),
		},
		opts: opts,
	}, nil
}

func MustNewGranularHistogram(opts prometheus.HistogramOpts, labels []string) GranularHistogram {
	result, err := NewGranularHistogram(granularLabelFilter, opts, labels)
	if err != nil {
		panic(err)
	}
	return result
}

func (m *granularHistogram) ToProm() *prometheus.HistogramVec {
	m.eval.Do(func() {
		m.labels = m.mustFilter(m.labels...)
		m.metric = NewHistogramVecWithPod(m.opts, m.labels)
	})
	return m.metric
}

func (m *granularHistogram) WithLabelValues(lvs ...string) prometheus.Observer {
	filtered := m.mustFilter(lvs...)
	return m.ToProm().WithLabelValues(filtered...)
}
