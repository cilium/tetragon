// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metrics

import (
	"fmt"
	"slices"

	"github.com/prometheus/client_golang/prometheus"
)

// Opts extends prometheus.Opts with constrained and unconstrained labels.
//
// If using granular wrappers for prometheus metrics, then constrained labels
// will be replaced with an empty string if a values outside of the list is
// passed.
//
// If using granular metric interface (either wrappers or custom metrics), then
// labels passed via type parameter:
// - are assumed to be unconstrained
// - will be added at the beginning of the final labels list
// - must not overlap with labels passed via Opts
type Opts struct {
	prometheus.Opts
	ConstrainedLabels   []ConstrainedLabel
	UnconstrainedLabels []UnconstrainedLabel
}

// HistogramOpts extends Opts with histogram-specific fields.
type HistogramOpts struct {
	Opts
	Buckets []float64
}

func NewOpts(
	namespace, subsystem, name, help string,
	constLabels prometheus.Labels, constrainedLabels []ConstrainedLabel, unconstrainedLabels []UnconstrainedLabel,
) Opts {
	return Opts{
		Opts: prometheus.Opts{
			Namespace:   namespace,
			Subsystem:   subsystem,
			Name:        name,
			Help:        help,
			ConstLabels: constLabels,
		},
		ConstrainedLabels:   constrainedLabels,
		UnconstrainedLabels: unconstrainedLabels,
	}
}

// getVariableLabels is a helper function to retrieve the full label list for
// a metric and check if the metric is constrained.
//
// The return type is prometheus.ConstrainedLabels, which can be passed (as
// prometheus.ConstrainableLabels) to functions from prometheus library that
// define metrics with variable labels. Note that despite the same name,
// prometheus.ConstrainedLabels type shouldn't be confused with
// ConstrainedLabels field in Opts struct. The returned list contains all
// labels, not only those defined as constrained.
//
// The returned label list follows the order:
// 1. FilteredLabels passed via type parameter (assumed to be unconstrained)
// 2. opts.ConstrainedLabels
// 3. opts.UnconstrainedLabels
//
// Labels passed via opts.ConstrainedLabels will be constrained by prometheus
// library. If a value outside of the list is passed, it will be replaced with
// an empty string.
func getVariableLabels[L FilteredLabels](opts *Opts) (prometheus.ConstrainedLabels, bool, error) {
	var dummy L
	commonLabels := dummy.Keys()
	labelsErr := fmt.Errorf("extra labels can't contain any of the following: %v", commonLabels)

	promLabels := make(
		[]prometheus.ConstrainedLabel,
		len(commonLabels)+len(opts.ConstrainedLabels)+len(opts.UnconstrainedLabels),
	)

	// first FilteredLabels
	current := promLabels
	for i, label := range commonLabels {
		current[i] = prometheus.ConstrainedLabel{
			Name: label,
		}
	}
	// second constrained labels
	current = current[len(commonLabels):]
	for i, label := range opts.ConstrainedLabels {
		if slices.Contains(commonLabels, label.Name) {
			return nil, false, labelsErr
		}
		current[i] = prometheus.ConstrainedLabel{
			Name: label.Name,
			Constraint: func(value string) string {
				for _, v := range label.Values {
					if value == v {
						return value
					}
				}
				// If the value is not in the list of possible values,
				// replace it with an empty string.
				return ""
			},
		}
	}
	// third unconstrained labels
	current = current[len(opts.ConstrainedLabels):]
	for i, label := range opts.UnconstrainedLabels {
		if slices.Contains(commonLabels, label.Name) {
			return nil, false, labelsErr
		}
		current[i] = prometheus.ConstrainedLabel{
			Name: label.Name,
		}
	}

	// check if labels are constrained
	constrained := len(commonLabels) == 0 && len(opts.UnconstrainedLabels) == 0

	return promLabels, constrained, nil
}

// getVariableLabelNames is similar to getVariableLabels, but returns a list of
// label names (as []string) instead of prometheus.ConstrainedLabels.
//
// See getVariableLabels for the labels order.
func getVariableLabelNames[L FilteredLabels](opts *Opts) ([]string, bool, error) {
	labels, constrained, err := getVariableLabels[L](opts)
	labelNames := make([]string, len(labels))
	for i, label := range labels {
		labelNames[i] = label.Name
	}
	return labelNames, constrained, err
}
