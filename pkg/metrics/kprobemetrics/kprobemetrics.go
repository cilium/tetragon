// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package kprobemetrics

import (
	"maps"
	"slices"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
)

type MergeErrorType int

const (
	MergeErrorTypeEnter MergeErrorType = iota
	MergeErrorTypeExit
)

var mergeErrorTypeLabelValues = map[MergeErrorType]string{
	MergeErrorTypeEnter: "enter",
	MergeErrorTypeExit:  "exit",
}

func (t MergeErrorType) String() string {
	return mergeErrorTypeLabelValues[t]
}

var (
	currTypeLabel = metrics.ConstrainedLabel{
		Name:   "curr_type",
		Values: slices.Collect(maps.Values(mergeErrorTypeLabelValues)),
	}
	prevTypeLabel = metrics.ConstrainedLabel{
		Name:   "prev_type",
		Values: slices.Collect(maps.Values(mergeErrorTypeLabelValues)),
	}

	MergeErrors = metrics.MustNewCounter(
		metrics.NewOpts(
			consts.MetricsNamespace, "", "generic_kprobe_merge_errors_total",
			"The total number of failed attempts to merge a kprobe and kretprobe event.",
			nil,
			[]metrics.ConstrainedLabel{currTypeLabel, prevTypeLabel},
			[]metrics.UnconstrainedLabel{{Name: "curr_fn", ExampleValue: consts.ExampleKprobeLabel}, {Name: "prev_fn", ExampleValue: consts.ExampleKprobeLabel}},
		),
		nil,
	)
	MergeOkTotal = metrics.MustNewCounter(metrics.NewOpts(
		consts.MetricsNamespace, "", "generic_kprobe_merge_ok_total",
		"The total number of successful attempts to merge a kprobe and kretprobe event.",
		nil, nil, nil,
	), nil)
	MergePushed = metrics.MustNewCounter(metrics.NewOpts(
		consts.MetricsNamespace, "", "generic_kprobe_merge_pushed_total",
		"The total number of pushed events for later merge.",
		nil, nil, nil,
	), nil)
)

func RegisterMetrics(group metrics.Group) {
	group.MustRegister(MergeErrors)
	group.MustRegister(MergeOkTotal)
	group.MustRegister(MergePushed)
}

func InitMetricsForDocs() {
	// Initialize metrics with example labels
	for _, curr := range mergeErrorTypeLabelValues {
		for _, prev := range mergeErrorTypeLabelValues {
			MergeErrors.WithLabelValues(curr, prev, consts.ExampleKprobeLabel, consts.ExampleKprobeLabel).Add(0)
		}
	}
}

// Get a new handle on the mergeErrors metric for a current and previous function
// name and probe type
func GetMergeErrors(currFn, prevFn string, currType, prevType MergeErrorType) prometheus.Counter {
	return MergeErrors.WithLabelValues(currType.String(), prevType.String(), currFn, prevFn)
}

// Increment the mergeErrors metric for a current and previous function
// name and probe type
func MergeErrorsInc(currFn, prevFn string, currType, prevType MergeErrorType) {
	GetMergeErrors(currFn, prevFn, currType, prevType).Inc()
}

func MergeOkTotalInc() {
	MergeOkTotal.WithLabelValues().Inc()
}

func MergePushedInc() {
	MergePushed.WithLabelValues().Inc()
}
