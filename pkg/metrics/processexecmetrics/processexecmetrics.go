// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package processexecmetrics

import (
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	MissingParentErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "exec_missing_parent_errors",
		Help:        "The total of times a given parent exec id could not be found in an exec event.",
		ConstLabels: nil,
	}, []string{"parent_exec_id"})
	SameExecIdErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "exec_parent_child_same_id_errors",
		Help:        "The total of times an error occurs due to a parent and child process have the same exec id.",
		ConstLabels: nil,
	}, []string{"exec_id"})
)

// Get a new handle on the missingParentErrors metric for an execId
func GetMissingParent(execId string) prometheus.Counter {
	return MissingParentErrors.WithLabelValues(execId)
}

// Increment the missingParentErrors metric for an execId
func MissingParentInc(execId string) {
	GetMissingParent(execId).Inc()
}

// Get a new handle on the sameExecIdErrors metric for an execId
func GetSameExecId(execId string) prometheus.Counter {
	return SameExecIdErrors.WithLabelValues(execId)
}

// Increment the sameExecIdErrors metric for an execId
func SameExecIdInc(execId string) {
	GetSameExecId(execId).Inc()
}
