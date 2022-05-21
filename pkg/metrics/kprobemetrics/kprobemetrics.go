// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package kprobemetrics

import (
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	mergeErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:        consts.MetricNamePrefix + "generic_kprobe_merge_errors",
		Help:        "The total number of failed attempts to merge a kprobe and kretprobe event.",
		ConstLabels: nil,
	}, []string{"curr_fn", "curr_type", "prev_fn", "prev_type"})
)

// Get a new handle on the mergeErrors metric for a current and previous function
// name and probe type
func MergeErrors(currFn, currType, prevFn, prevType string) prometheus.Counter {
	return mergeErrors.WithLabelValues(currFn, currType, prevFn, prevType)
}

// Increment the mergeErrors metric for a current and previous function
// name and probe type
func MergeErrorsInc(currFn, currType, prevFn, prevType string) {
	MergeErrors(currFn, currType, prevFn, prevType).Inc()
}
