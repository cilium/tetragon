// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package processexecmetrics

import (
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	missingParentErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:        consts.MetricNamePrefix + "exec_missing_parent_errors",
		Help:        "The total of times a given parent exec id could not be found in an exec event.",
		ConstLabels: nil,
	}, []string{"parent_exec_id"})
	sameExecIdErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:        consts.MetricNamePrefix + "exec_parent_child_same_id_errors",
		Help:        "The total of times an error occurs due to a parent and child process have the same exec id.",
		ConstLabels: nil,
	}, []string{"exec_id"})
)

// Get a new handle on the missingParentErrors metric for an execId
func MissingParent(execId string) prometheus.Counter {
	return missingParentErrors.WithLabelValues(execId)
}

// Increment the missingParentErrors metric for an execId
func MissingParentInc(execId string) {
	MissingParent(execId).Inc()
}

// Get a new handle on the sameExecIdErrors metric for an execId
func SameExecId(execId string) prometheus.Counter {
	return sameExecIdErrors.WithLabelValues(execId)
}

// Increment the sameExecIdErrors metric for an execId
func SameExecIdInc(execId string) {
	SameExecId(execId).Inc()
}
