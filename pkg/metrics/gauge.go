// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

type initGaugeFunc func(*prometheus.GaugeVec)

// NewGaugeVecWithPod is a wrapper around prometheus.NewGaugeVec that also
// registers the metric to be cleaned up when a pod is deleted.
//
// See NewCounterVecWithPod for usage notes.
func NewGaugeVecWithPod(opts prometheus.GaugeOpts, labels []string) *prometheus.GaugeVec {
	metric := prometheus.NewGaugeVec(opts, labels)
	metricsWithPodMutex.Lock()
	metricsWithPod = append(metricsWithPod, metric.MetricVec)
	metricsWithPodMutex.Unlock()
	return metric
}

// NewGaugeVecWithPodV2 is a wrapper around prometheus.V2.NewGaugeVec that also
// registers the metric to be cleaned up when a pod is deleted.
//
// See NewCounterVecWithPod for usage notes.
func NewGaugeVecWithPodV2(opts prometheus.GaugeVecOpts) *prometheus.GaugeVec {
	metric := prometheus.V2.NewGaugeVec(opts)
	metricsWithPodMutex.Lock()
	metricsWithPod = append(metricsWithPod, metric.MetricVec)
	metricsWithPodMutex.Unlock()
	return metric
}

// GranularGauge wraps prometheus.GaugeVec and implements CollectorWithInit.
type GranularGauge[L FilteredLabels] struct {
	metric      *prometheus.GaugeVec
	constrained bool
	initFunc    initGaugeFunc
	initForDocs func()
}

// NewGranularGauge creates a new GranularGauge.
//
// See NewGranularCounter for usage notes.
func NewGranularGauge[L FilteredLabels](opts Opts, init initGaugeFunc) (*GranularGauge[L], error) {
	labels, constrained, err := getVariableLabels[L](&opts)
	if err != nil {
		return nil, err
	}

	promOpts := prometheus.GaugeVecOpts{
		GaugeOpts: prometheus.GaugeOpts{
			Namespace:   opts.Namespace,
			Subsystem:   opts.Subsystem,
			Name:        opts.Name,
			Help:        opts.Help,
			ConstLabels: opts.ConstLabels,
		},
		VariableLabels: labels,
	}
	var metric *prometheus.GaugeVec
	if promContainsLabel(labels, "pod") && promContainsLabel(labels, "namespace") {
		// set up metric to be deleted when a pod is deleted
		metric = NewGaugeVecWithPodV2(promOpts)
	} else {
		metric = prometheus.V2.NewGaugeVec(promOpts)
	}

	initMetric := func(lvs ...string) {
		metric.WithLabelValues(lvs...).Set(0)
	}

	// If metric is constrained, default to initializing all combinations of
	// labels. Note that in such case the initialization function doesn't
	// reference the wrapped metric passed as an argument because this metric
	// is captured already in initMetric closure.
	if constrained && init == nil {
		init = func(_ *prometheus.GaugeVec) {
			initAllCombinations(initMetric, opts.ConstrainedLabels)
		}
	}

	return &GranularGauge[L]{
		metric:      metric,
		constrained: constrained,
		initFunc:    init,
		initForDocs: func() {
			initForDocs[L](initMetric, opts.ConstrainedLabels, opts.UnconstrainedLabels)
		},
	}, nil
}

// MustNewGranularGauge is a convenience function that wraps
// NewGranularGauge and panics on error.
//
// See MustNewGranularCounter for usage notes.
//
// DEPRECATED: Use MustNewGranularGaugeWithInit instead.
func MustNewGranularGauge[L FilteredLabels](promOpts prometheus.GaugeOpts, extraLabels []string) *GranularGauge[L] {
	unconstrained := stringToUnconstrained(extraLabels)
	opts := Opts{
		Opts:                prometheus.Opts(promOpts),
		UnconstrainedLabels: unconstrained,
	}
	metric, err := NewGranularGauge[L](opts, nil)
	if err != nil {
		panic(err)
	}
	return metric
}

// MustNewGranularGaugeWithInit is a convenience function that wraps
// NewGranularGauge and panics on error.
func MustNewGranularGaugeWithInit[L FilteredLabels](opts Opts, init initGaugeFunc) *GranularGauge[L] {
	metric, err := NewGranularGauge[L](opts, init)
	if err != nil {
		panic(err)
	}
	return metric
}

// Describe implements CollectorWithInit (prometheus.Collector).
func (m *GranularGauge[L]) Describe(ch chan<- *prometheus.Desc) {
	m.metric.Describe(ch)
}

// Collect implements CollectorWithInit (prometheus.Collector).
func (m *GranularGauge[L]) Collect(ch chan<- prometheus.Metric) {
	m.metric.Collect(ch)
}

// IsConstrained implements CollectorWithInit.
func (m *GranularGauge[L]) IsConstrained() bool {
	return m.constrained
}

// Init implements CollectorWithInit.
func (m *GranularGauge[L]) Init() {
	if m.initFunc != nil {
		m.initFunc(m.metric)
	}
}

// InitForDocs implements CollectorWithInit.
func (m *GranularGauge[L]) InitForDocs() {
	if m.initForDocs != nil {
		m.initForDocs()
	}
}

// WithLabelValues is similar to WithLabelValues method from prometheus
// package, but takes generic FilteredLabels as the first argument. The
// following arguments are values of first constrained labels, then
// unconstrained labels.
func (m *GranularGauge[L]) WithLabelValues(commonLvs *L, lvs ...string) prometheus.Gauge {
	if commonLvs != nil {
		lvs = append((*commonLvs).Values(), lvs...)
	}
	return m.metric.WithLabelValues(lvs...)
}

// Gauge wraps prometheus.GaugeVec and implements CollectorWithInit.
//
// The only difference between GranularGauge[FilteredLabels] and Gauge is
// WithLabelValues method, which in the latter doesn't take generic
// FilteredLabels argument. We can also use GranularGauge[NilLabels] to
// define gauges with no configurable labels, but then we have to pass
// an additional nil argument to WithLabelValues. A separate type is provided
// for convenience and easy migration.
type Gauge struct {
	*GranularGauge[NilLabels]
}

// NewGauge creates a new Gauge.
//
// See NewGranularCounter for usage notes.
func NewGauge(opts Opts, init initGaugeFunc) (*Gauge, error) {
	metric, err := NewGranularGauge[NilLabels](opts, init)
	if err != nil {
		return nil, err
	}
	return &Gauge{metric}, nil
}

// MustNewGauge is a convenience function that wraps NewGauge and panics on
// error.
func MustNewGauge(opts Opts, init initGaugeFunc) *Gauge {
	metric, err := NewGauge(opts, init)
	if err != nil {
		panic(err)
	}
	return metric
}

// Describe implements CollectorWithInit (prometheus.Collector).
func (m *Gauge) Describe(ch chan<- *prometheus.Desc) {
	m.GranularGauge.Describe(ch)
}

// Collect implements CollectorWithInit (prometheus.Collector).
func (m *Gauge) Collect(ch chan<- prometheus.Metric) {
	m.GranularGauge.Collect(ch)
}

// IsConstrained implements CollectorWithInit.
func (m *Gauge) IsConstrained() bool {
	return m.GranularGauge.IsConstrained()
}

// Init implements CollectorWithInit.
func (m *Gauge) Init() {
	m.GranularGauge.Init()
}

// InitForDocs implements CollectorWithInit.
func (m *Gauge) InitForDocs() {
	m.GranularGauge.InitForDocs()
}

// WithLabelValues is similar to WithLabelValues method from prometheus
// package. The arguments are values of first constrained labels, then
// unconstrained labels.
func (m *Gauge) WithLabelValues(lvs ...string) prometheus.Gauge {
	return m.GranularGauge.WithLabelValues(nil, lvs...)
}

// granularCustomGauge implements GranularCustomMetric.
type granularCustomGauge[L FilteredLabels] struct {
	desc        *prometheus.Desc
	constrained bool
}

// NewGranularCustomGauge creates a new granularCustomGauge.
func NewGranularCustomGauge[L FilteredLabels](opts Opts) (GranularCustomMetric[L], error) {
	desc, constrained, err := getDesc[L](&opts)
	if err != nil {
		return nil, err
	}

	return &granularCustomGauge[L]{
		desc:        desc,
		constrained: constrained,
	}, nil
}

// MustNewGranularCustomGauge is a convenience function that wraps
// NewGranularCustomGauge and panics on error.
func MustNewGranularCustomGauge[L FilteredLabels](opts Opts) GranularCustomMetric[L] {
	metric, err := NewGranularCustomGauge[L](opts)
	if err != nil {
		panic(err)
	}
	return metric
}

// Desc implements GranularCustomMetric.
func (m *granularCustomGauge[L]) Desc() *prometheus.Desc {
	return m.desc
}

// MustMetric implements GranularCustomMetric.
func (m *granularCustomGauge[L]) MustMetric(value float64, commonLvs *L, lvs ...string) prometheus.Metric {
	if commonLvs != nil {
		lvs = append((*commonLvs).Values(), lvs...)
	}
	return prometheus.MustNewConstMetric(m.desc, prometheus.GaugeValue, value, lvs...)
}

// IsConstrained implements GranularCustomMetric.
func (m *granularCustomGauge[L]) IsConstrained() bool {
	return m.constrained
}

// customGauge implements CustomMetric.
type customGauge struct {
	*granularCustomGauge[NilLabels]
}

// NewCustomGauge creates a new customGauge.
func NewCustomGauge(opts Opts) (CustomMetric, error) {
	metric, err := NewGranularCustomGauge[NilLabels](opts)
	if err != nil {
		return nil, err
	}
	gauge, ok := metric.(*granularCustomGauge[NilLabels])
	if !ok {
		return nil, ErrInvalidMetricType
	}
	return &customGauge{gauge}, nil
}

// MustNewCustomGauge is a convenience function that wraps NewCustomGauge
// and panics on error.
func MustNewCustomGauge(opts Opts) CustomMetric {
	metric, err := NewCustomGauge(opts)
	if err != nil {
		panic(err)
	}
	return metric
}

// Desc implements CustomMetric.
func (m *customGauge) Desc() *prometheus.Desc {
	return m.granularCustomGauge.Desc()
}

// MustMetric implements CustomMetric.
func (m *customGauge) MustMetric(value float64, lvs ...string) prometheus.Metric {
	return m.granularCustomGauge.MustMetric(value, nil, lvs...)
}

// IsConstrained implements CustomMetric.
func (m *customGauge) IsConstrained() bool {
	return m.granularCustomGauge.IsConstrained()
}
