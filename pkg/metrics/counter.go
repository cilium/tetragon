// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

type initCounterFunc func(*prometheus.CounterVec)

// NewCounterVecWithPod is a wrapper around prometheus.NewCounterVec that also
// registers the metric to be cleaned up when a pod is deleted.
//
// It should be used only to register metrics that have "pod" and "namespace"
// labels. Using it for metrics without these labels won't break anything, but
// might add an unnecessary overhead.
func NewCounterVecWithPod(opts prometheus.CounterOpts, labels []string) *prometheus.CounterVec {
	metric := prometheus.NewCounterVec(opts, labels)
	metricsWithPodMutex.Lock()
	metricsWithPod = append(metricsWithPod, metric.MetricVec)
	metricsWithPodMutex.Unlock()
	return metric
}

// NewCounterVecWithPodV2 is a wrapper around prometheus.V2.NewCounterVec that also
// registers the metric to be cleaned up when a pod is deleted.
//
// See NewCounterVecWithPod for usage notes.
func NewCounterVecWithPodV2(opts prometheus.CounterVecOpts) *prometheus.CounterVec {
	metric := prometheus.V2.NewCounterVec(opts)
	metricsWithPodMutex.Lock()
	metricsWithPod = append(metricsWithPod, metric.MetricVec)
	metricsWithPodMutex.Unlock()
	return metric
}

// GranularCounter wraps prometheus.CounterVec and implements CollectorWithInit.
type GranularCounter[L FilteredLabels] struct {
	metric      *prometheus.CounterVec
	constrained bool
	initFunc    initCounterFunc
	initForDocs func()
}

// NewGranularCounter creates a new GranularCounter.
//
// The init argument is a function that initializes the metric with some label
// values. Doing so allows us to keep resources usage predictable. If the
// metric is constrained (i.e. type parameter is NilLabels and there are no
// unconstrained labels) and init is nil, then the metric will be initialized
// with all possible combinations of labels. If the metric is unconstrained, it
// won't be initialized by default.
//
// Pass an init function in the following cases:
//   - metric is constrained but not all combinations of labels make sense
//     (e.g. there is a hierarchy between labels or two labels represent the
//     same thing in different formats, or two labels are mutually exclusive).
//   - metric is unconstrained, but some of the unconstrained label values are
//     known beforehand, so can be initialized.
//   - you want to disable default initialization - pass
//     func(*prometheus.CounterVec) {} in such case
func NewGranularCounter[L FilteredLabels](opts Opts, init initCounterFunc) (*GranularCounter[L], error) {
	labels, constrained, err := getVariableLabels[L](&opts)
	if err != nil {
		return nil, err
	}

	promOpts := prometheus.CounterVecOpts{
		CounterOpts: prometheus.CounterOpts{
			Namespace:   opts.Namespace,
			Subsystem:   opts.Subsystem,
			Name:        opts.Name,
			Help:        opts.Help,
			ConstLabels: opts.ConstLabels,
		},
		VariableLabels: labels,
	}
	var metric *prometheus.CounterVec
	if promContainsLabel(labels, "pod") && promContainsLabel(labels, "namespace") {
		// set up metric to be deleted when a pod is deleted
		metric = NewCounterVecWithPodV2(promOpts)
	} else {
		metric = prometheus.V2.NewCounterVec(promOpts)
	}

	initMetric := func(lvs ...string) {
		metric.WithLabelValues(lvs...).Add(0)
	}

	// If metric is constrained, default to initializing all combinations of
	// labels. Note that in such case the initialization function doesn't
	// reference the wrapped metric passed as an argument because this metric
	// is captured already in initMetric closure.
	if constrained && init == nil {
		init = func(_ *prometheus.CounterVec) {
			initAllCombinations(initMetric, opts.ConstrainedLabels)
		}
	}

	return &GranularCounter[L]{
		metric:      metric,
		constrained: constrained,
		initFunc:    init,
		initForDocs: func() {
			initForDocs[L](initMetric, opts.ConstrainedLabels, opts.UnconstrainedLabels)
		},
	}, nil
}

// MustNewGranularCounter is a convenience function that wraps
// NewGranularCounter and panics on error.
//
// NOTE: The function takes different arguments than NewGranularCounter, to
// provide a bridge between the new metrics library and the existing code
// defining metrics.
//
// DEPRECATED: Use MustNewGranularCounterWithInit instead.
func MustNewGranularCounter[L FilteredLabels](promOpts prometheus.CounterOpts, extraLabels []string) *GranularCounter[L] {
	unconstrained := stringToUnconstrained(extraLabels)
	opts := Opts{
		Opts:                prometheus.Opts(promOpts),
		UnconstrainedLabels: unconstrained,
	}
	metric, err := NewGranularCounter[L](opts, nil)
	if err != nil {
		panic(err)
	}
	return metric
}

// MustNewGranularCounterWithInit is a convenience function that wraps
// NewGranularCounter and panics on error.
func MustNewGranularCounterWithInit[L FilteredLabels](opts Opts, init initCounterFunc) *GranularCounter[L] {
	metric, err := NewGranularCounter[L](opts, init)
	if err != nil {
		panic(err)
	}
	return metric
}

// Describe implements CollectorWithInit (prometheus.Collector).
func (m *GranularCounter[L]) Describe(ch chan<- *prometheus.Desc) {
	m.metric.Describe(ch)
}

// Collect implements CollectorWithInit (prometheus.Collector).
func (m *GranularCounter[L]) Collect(ch chan<- prometheus.Metric) {
	m.metric.Collect(ch)
}

// IsConstrained implements CollectorWithInit.
func (m *GranularCounter[L]) IsConstrained() bool {
	return m.constrained
}

// Init implements CollectorWithInit.
func (m *GranularCounter[L]) Init() {
	if m.initFunc != nil {
		m.initFunc(m.metric)
	}
}

// InitForDocs implements CollectorWithInit.
func (m *GranularCounter[L]) InitForDocs() {
	if m.initForDocs != nil {
		m.initForDocs()
	}
}

// WithLabelValues is similar to WithLabelValues method from prometheus
// package, but takes generic FilteredLabels as the first argument. The
// following arguments are values of first constrained labels, then
// unconstrained labels.
func (m *GranularCounter[L]) WithLabelValues(commonLvs *L, lvs ...string) prometheus.Counter {
	if commonLvs != nil {
		lvs = append((*commonLvs).Values(), lvs...)
	}
	return m.metric.WithLabelValues(lvs...)
}

// Counter wraps prometheus.CounterVec and implements CollectorWithInit.
//
// The only difference between GranularCounter[FilteredLabels] and Counter is
// WithLabelValues method, which in the latter doesn't take generic
// FilteredLabels argument. We can also use GranularCounter[NilLabels] to
// define counters with no configurable labels, but then we have to pass
// an additional nil argument to WithLabelValues. A separate type is provided
// for convenience and easy migration.
type Counter struct {
	*GranularCounter[NilLabels]
}

// NewCounter creates a new Counter.
//
// See NewGranularCounter for usage notes.
func NewCounter(opts Opts, init initCounterFunc) (*Counter, error) {
	metric, err := NewGranularCounter[NilLabels](opts, init)
	if err != nil {
		return nil, err
	}
	return &Counter{metric}, nil
}

// MustNewCounter is a convenience function that wraps NewCounter and panics on
// error.
func MustNewCounter(opts Opts, init initCounterFunc) *Counter {
	metric, err := NewCounter(opts, init)
	if err != nil {
		panic(err)
	}
	return metric
}

// Describe implements CollectorWithInit (prometheus.Collector).
func (m *Counter) Describe(ch chan<- *prometheus.Desc) {
	m.GranularCounter.Describe(ch)
}

// Collect implements CollectorWithInit (prometheus.Collector).
func (m *Counter) Collect(ch chan<- prometheus.Metric) {
	m.GranularCounter.Collect(ch)
}

// IsConstrained implements CollectorWithInit.
func (m *Counter) IsConstrained() bool {
	return m.GranularCounter.IsConstrained()
}

// Init implements CollectorWithInit.
func (m *Counter) Init() {
	m.GranularCounter.Init()
}

// InitForDocs implements CollectorWithInit.
func (m *Counter) InitForDocs() {
	m.GranularCounter.InitForDocs()
}

// WithLabelValues is similar to WithLabelValues method from prometheus
// package. The arguments are values of first constrained labels, then
// unconstrained labels.
func (m *Counter) WithLabelValues(lvs ...string) prometheus.Counter {
	return m.GranularCounter.WithLabelValues(nil, lvs...)
}

// granularCustomCounter implements GranularCustomMetric.
type granularCustomCounter[L FilteredLabels] struct {
	desc        *prometheus.Desc
	constrained bool
}

// NewGranularCustomCounter creates a new granularCustomCounter.
func NewGranularCustomCounter[L FilteredLabels](opts Opts) (GranularCustomMetric[L], error) {
	desc, constrained, err := getDesc[L](&opts)
	if err != nil {
		return nil, err
	}

	return &granularCustomCounter[L]{
		desc:        desc,
		constrained: constrained,
	}, nil
}

// MustNewGranularCustomCounter is a convenience function that wraps
// NewGranularCustomCounter and panics on error.
func MustNewGranularCustomCounter[L FilteredLabels](opts Opts) GranularCustomMetric[L] {
	metric, err := NewGranularCustomCounter[L](opts)
	if err != nil {
		panic(err)
	}
	return metric
}

// Desc implements GranularCustomMetric.
func (m *granularCustomCounter[L]) Desc() *prometheus.Desc {
	return m.desc
}

// MustMetric implements GranularCustomMetric.
func (m *granularCustomCounter[L]) MustMetric(value float64, commonLvs *L, lvs ...string) prometheus.Metric {
	if commonLvs != nil {
		lvs = append((*commonLvs).Values(), lvs...)
	}
	return prometheus.MustNewConstMetric(m.desc, prometheus.CounterValue, value, lvs...)
}

// IsConstrained implements GranularCustomMetric.
func (m *granularCustomCounter[L]) IsConstrained() bool {
	return m.constrained
}

// customCounter implements CustomMetric.
type customCounter struct {
	*granularCustomCounter[NilLabels]
}

// NewCustomCounter creates a new customCounter.
func NewCustomCounter(opts Opts) (CustomMetric, error) {
	metric, err := NewGranularCustomCounter[NilLabels](opts)
	if err != nil {
		return nil, err
	}
	counter, ok := metric.(*granularCustomCounter[NilLabels])
	if !ok {
		return nil, ErrInvalidMetricType
	}
	return &customCounter{counter}, nil
}

// MustNewCustomCounter is a convenience function that wraps NewCustomCounter
// and panics on error.
func MustNewCustomCounter(opts Opts) CustomMetric {
	metric, err := NewCustomCounter(opts)
	if err != nil {
		panic(err)
	}
	return metric
}

// Desc implements CustomMetric.
func (m *customCounter) Desc() *prometheus.Desc {
	return m.granularCustomCounter.Desc()
}

// MustMetric implements CustomMetric.
func (m *customCounter) MustMetric(value float64, lvs ...string) prometheus.Metric {
	return m.granularCustomCounter.MustMetric(value, nil, lvs...)
}

// IsConstrained implements CustomMetric.
func (m *customCounter) IsConstrained() bool {
	return m.granularCustomCounter.IsConstrained()
}
