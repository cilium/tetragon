// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package kprobemetrics

import (
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
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
	MergeErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "generic_kprobe_merge_errors_total",
		Help:        "The total number of failed attempts to merge a kprobe and kretprobe event.",
		ConstLabels: nil,
	}, []string{"curr_fn", "curr_type", "prev_fn", "prev_type"})
	MergeOkTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "generic_kprobe_merge_ok_total",
		Help:        "The total number of successful attempts to merge a kprobe and kretprobe event.",
		ConstLabels: nil,
	})
	MergePushed = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "generic_kprobe_merge_pushed_total",
		Help:        "The total number of pushed events for later merge.",
		ConstLabels: nil,
	})
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
			MergeErrors.WithLabelValues(consts.ExampleKprobeLabel, curr, consts.ExampleKprobeLabel, prev).Add(0)
		}
	}
}

// Get a new handle on the mergeErrors metric for a current and previous function
// name and probe type
func GetMergeErrors(currFn, prevFn string, currType, prevType MergeErrorType) prometheus.Counter {
	return MergeErrors.WithLabelValues(currFn, prevFn, currType.String(), prevType.String())
}

// Increment the mergeErrors metric for a current and previous function
// name and probe type
func MergeErrorsInc(currFn, prevFn string, currType, prevType MergeErrorType) {
	GetMergeErrors(currFn, prevFn, currType, prevType).Inc()
}

func MergeOkTotalInc() {
	MergeOkTotal.Inc()
}

func MergePushedInc() {
	MergePushed.Inc()
}
