// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

type initHistogramFunc func(*prometheus.HistogramVec)

// NewHistogramVecWithPod is a wrapper around prometheus.NewHistogramVec that also
// registers the metric to be cleaned up when a pod is deleted.
//
// See NewCounterVecWithPod for usage notes.
func NewHistogramVecWithPod(opts prometheus.HistogramOpts, labels []string) *prometheus.HistogramVec {
	metric := prometheus.NewHistogramVec(opts, labels)
	metricsWithPodMutex.Lock()
	metricsWithPod = append(metricsWithPod, metric.MetricVec)
	metricsWithPodMutex.Unlock()
	return metric
}

// NewHistogramVecWithPodV2 is a wrapper around prometheus.V2.NewHistogramVec that also
// registers the metric to be cleaned up when a pod is deleted.
//
// See NewCounterVecWithPod for usage notes.
func NewHistogramVecWithPodV2(opts prometheus.HistogramVecOpts) *prometheus.HistogramVec {
	metric := prometheus.V2.NewHistogramVec(opts)
	metricsWithPodMutex.Lock()
	metricsWithPod = append(metricsWithPod, metric.MetricVec)
	metricsWithPodMutex.Unlock()
	return metric
}

// GranularHistogram wraps prometheus.HistogramVec and implements CollectorWithInit.
type GranularHistogram[L FilteredLabels] struct {
	metric      *prometheus.HistogramVec
	constrained bool
	initFunc    initHistogramFunc
	initForDocs func()
}

// NewGranularHistogram creates a new GranularHistogram.
//
// See NewGranularCounter for usage notes.
func NewGranularHistogram[L FilteredLabels](opts HistogramOpts, init initHistogramFunc) (*GranularHistogram[L], error) {
	labels, constrained, err := getVariableLabels[L](&opts.Opts)
	if err != nil {
		return nil, err
	}

	promOpts := prometheus.HistogramVecOpts{
		HistogramOpts: prometheus.HistogramOpts{
			Namespace:   opts.Namespace,
			Subsystem:   opts.Subsystem,
			Name:        opts.Name,
			Help:        opts.Help,
			ConstLabels: opts.ConstLabels,
			Buckets:     opts.Buckets,
		},
		VariableLabels: labels,
	}
	var metric *prometheus.HistogramVec
	if promContainsLabel(labels, "pod") && promContainsLabel(labels, "namespace") {
		// set up metric to be deleted when a pod is deleted
		metric = NewHistogramVecWithPodV2(promOpts)
	} else {
		metric = prometheus.V2.NewHistogramVec(promOpts)
	}

	initMetric := func(lvs ...string) {
		metric.WithLabelValues(lvs...)
	}

	// If metric is constrained, default to initializing all combinations of
	// labels. Note that in such case the initialization function doesn't
	// reference the wrapped metric passed as an argument because this metric
	// is captured already in initMetric closure.
	if constrained && init == nil {
		init = func(_ *prometheus.HistogramVec) {
			initAllCombinations(initMetric, opts.ConstrainedLabels)
		}
	}

	return &GranularHistogram[L]{
		metric:      metric,
		constrained: constrained,
		initFunc:    init,
		initForDocs: func() {
			initForDocs[L](initMetric, opts.ConstrainedLabels, opts.UnconstrainedLabels)
		},
	}, nil
}

// MustNewGranularHistogram is a convenience function that wraps
// NewGranularHistogram and panics on error.
//
// See MustNewGranularCounter for usage notes.
//
// DEPRECATED: Use MustNewGranularHistogramWithInit instead.
func MustNewGranularHistogram[L FilteredLabels](promOpts prometheus.HistogramOpts, extraLabels []string) *GranularHistogram[L] {
	unconstrained := stringToUnconstrained(extraLabels)
	opts := HistogramOpts{
		Opts: Opts{
			Opts: prometheus.Opts{
				Namespace:   promOpts.Namespace,
				Subsystem:   promOpts.Subsystem,
				Name:        promOpts.Name,
				Help:        promOpts.Help,
				ConstLabels: promOpts.ConstLabels,
			},
			UnconstrainedLabels: unconstrained,
		},
		Buckets: promOpts.Buckets,
	}
	metric, err := NewGranularHistogram[L](opts, nil)
	if err != nil {
		panic(err)
	}
	return metric
}

// MustNewGranularHistogramWithInit is a convenience function that wraps
// NewGranularHistogram and panics on error.
func MustNewGranularHistogramWithInit[L FilteredLabels](opts HistogramOpts, init initHistogramFunc) *GranularHistogram[L] {
	metric, err := NewGranularHistogram[L](opts, init)
	if err != nil {
		panic(err)
	}
	return metric
}

// Describe implements CollectorWithInit (prometheus.Collector).
func (m *GranularHistogram[L]) Describe(ch chan<- *prometheus.Desc) {
	m.metric.Describe(ch)
}

// Collect implements CollectorWithInit (prometheus.Collector).
func (m *GranularHistogram[L]) Collect(ch chan<- prometheus.Metric) {
	m.metric.Collect(ch)
}

// IsConstrained implements CollectorWithInit.
func (m *GranularHistogram[L]) IsConstrained() bool {
	return m.constrained
}

// Init implements CollectorWithInit.
func (m *GranularHistogram[L]) Init() {
	if m.initFunc != nil {
		m.initFunc(m.metric)
	}
}

// InitForDocs implements CollectorWithInit.
func (m *GranularHistogram[L]) InitForDocs() {
	if m.initForDocs != nil {
		m.initForDocs()
	}
}

// WithLabelValues is similar to WithLabelValues method from prometheus
// package, but takes generic FilteredLabels as the first argument. The
// following arguments are values of first constrained labels, then
// unconstrained labels.
func (m *GranularHistogram[L]) WithLabelValues(commonLvs *L, lvs ...string) prometheus.Observer {
	if commonLvs != nil {
		lvs = append((*commonLvs).Values(), lvs...)
	}
	return m.metric.WithLabelValues(lvs...)
}

// Histogram wraps prometheus.HistogramVec and implements CollectorWithInit.
//
// The only difference between GranularHistogram[FilteredLabels] and Histogram is
// WithLabelValues method, which in the latter doesn't take generic
// FilteredLabels argument. We can also use GranularHistogram[NilLabels] to
// define histograms with no configurable labels, but then we have to pass
// an additional nil argument to WithLabelValues. A separate type is provided
// for convenience and easy migration.
type Histogram struct {
	*GranularHistogram[NilLabels]
}

// NewHistogram creates a new Histogram.
//
// See NewGranularCounter for usage notes.
func NewHistogram(opts HistogramOpts, init initHistogramFunc) (*Histogram, error) {
	metric, err := NewGranularHistogram[NilLabels](opts, init)
	if err != nil {
		return nil, err
	}
	return &Histogram{metric}, nil
}

// MustNewHistogram is a convenience function that wraps NewHistogram and panics on
// error.
func MustNewHistogram(opts HistogramOpts, init initHistogramFunc) *Histogram {
	metric, err := NewHistogram(opts, init)
	if err != nil {
		panic(err)
	}
	return metric
}

// Describe implements CollectorWithInit (prometheus.Collector).
func (m *Histogram) Describe(ch chan<- *prometheus.Desc) {
	m.GranularHistogram.Describe(ch)
}

// Collect implements CollectorWithInit (prometheus.Collector).
func (m *Histogram) Collect(ch chan<- prometheus.Metric) {
	m.GranularHistogram.Collect(ch)
}

// IsConstrained implements CollectorWithInit.
func (m *Histogram) IsConstrained() bool {
	return m.GranularHistogram.IsConstrained()
}

// Init implements CollectorWithInit.
func (m *Histogram) Init() {
	m.GranularHistogram.Init()
}

// InitForDocs implements CollectorWithInit.
func (m *Histogram) InitForDocs() {
	m.GranularHistogram.InitForDocs()
}

// WithLabelValues is similar to WithLabelValues method from prometheus
// package. The arguments are values of first constrained labels, then
// unconstrained labels.
func (m *Histogram) WithLabelValues(lvs ...string) prometheus.Observer {
	return m.GranularHistogram.WithLabelValues(nil, lvs...)
}
