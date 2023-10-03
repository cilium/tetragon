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

type GranularCounter interface {
	ToProm() *prometheus.CounterVec
	WithLabelValues(lvs ...string) prometheus.Counter
	filter(labels ...string) ([]string, error)
	mustFilter(labels ...string) []string
}

type granularCounter struct {
	labels      []string
	labelFilter *LabelFilter
	eval        sync.Once
	metric      *prometheus.CounterVec
	opts        prometheus.CounterOpts
}

func NewGranularCounter(f *LabelFilter, opts prometheus.CounterOpts, labels []string) (GranularCounter, error) {
	for _, label := range labels {
		if slices.Contains(f.known, label) {
			return nil, fmt.Errorf("passed labels can't contain any of the following: %v", f.known)
		}
	}
	return &granularCounter{
		labels:      append(labels, f.known...),
		labelFilter: f,
		opts:        opts,
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

// filter takes in string arguments and returns a slice of those strings omitting the labels not configured in the metric labelFilter.
// IMPORTANT! The filtered metric labels must be passed last and in the exact order of granularCounter.labelFilter.known.
func (m *granularCounter) filter(labels ...string) ([]string, error) {
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

func (m *granularCounter) mustFilter(labels ...string) []string {
	result, err := m.filter(labels...)
	if err != nil {
		panic(err)
	}
	return result
}
