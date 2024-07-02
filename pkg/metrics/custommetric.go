// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metrics

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"
)

var ErrInvalidMetricType = errors.New("invalid metric type")

type customMetric interface {
	Desc() *prometheus.Desc
	IsConstrained() bool
}

type CustomMetrics []customMetric

// GranularCustomMetric represents a metric collected independently of
// prometheus package, for example in a BPF map.
//
// It's intended to be used in a custom collector (see customcollector.go).
// The interface doesn't provide any validation, so it's entirely up to the
// collector implementer to guarantee metrics consistency, including enforcing
// labels constraints.
type GranularCustomMetric[L FilteredLabels] interface {
	customMetric
	MustMetric(value float64, commonLvs *L, lvs ...string) prometheus.Metric
}

// CustomMetric represents a metric collected independently of prometheus
// package that has no configurable labels.
//
// The only difference between GranularCustomMetric[FilteredLabels] and
// CustomMetric is MustMetric method, which in the latter doesn't take generic
// FilteredLabels argument. We can also use GranularCustomMetric[NilLabels] to
// define custom metrics with no configurable labels, but then we have to pass
// an additional nil argument to MustMetric. A separate interface is provided
// for convenience and easy migration.
//
// See GranularCustomMetric for usage notes.
type CustomMetric interface {
	customMetric
	MustMetric(value float64, lvs ...string) prometheus.Metric
}

// getDesc is a helper function to retrieve the descriptor for a metric and
// check if the metric is constrained.
//
// See getVariableLabels for the labels order.
func getDesc[L FilteredLabels](opts *Opts) (*prometheus.Desc, bool, error) {
	labels, constrained, err := getVariableLabelNames[L](opts)
	if err != nil {
		return nil, false, err
	}

	desc := prometheus.NewDesc(
		prometheus.BuildFQName(opts.Namespace, opts.Subsystem, opts.Name),
		opts.Help,
		labels,
		opts.ConstLabels,
	)
	return desc, constrained, nil
}
