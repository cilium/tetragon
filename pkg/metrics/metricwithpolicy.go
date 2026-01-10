// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metrics

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	metricsWithPolicy      []*prometheus.MetricVec
	metricsWithPolicyMutex sync.Mutex
)
func registerCounterVecForPolicyCleanup(metric *prometheus.CounterVec) {
	metricsWithPolicyMutex.Lock()
	metricsWithPolicy = append(metricsWithPolicy, metric.MetricVec)
	metricsWithPolicyMutex.Unlock()
}

// NewCounterVecWithPolicy is a wrapper around prometheus.NewCounterVec that also
// registers the metric to be cleaned up when a policy is deleted.
//
// It should be used only to register metrics that have "policy" label. Using it
// for metrics without this label won't break anything, but might add an
// unnecessary overhead.
func NewCounterVecWithPolicy(opts prometheus.CounterOpts, labels []string) *prometheus.CounterVec {
	metric := prometheus.NewCounterVec(opts, labels)
	registerCounterVecForPolicyCleanup(metric)
	return metric
}

// NewCounterVecWithPolicyV2 is a wrapper around prometheus.V2.NewCounterVec that also
// registers the metric to be cleaned up when a policy is deleted.
//
// See NewCounterVecWithPolicy for usage notes.
func NewCounterVecWithPolicyV2(opts prometheus.CounterVecOpts) *prometheus.CounterVec {
	metric := prometheus.V2.NewCounterVec(opts)
	registerCounterVecForPolicyCleanup(metric)
	return metric
}

// DeleteMetricsForPolicy removes all metric series for the given policy.
func DeleteMetricsForPolicy(policyName string) {
	metricsWithPolicyMutex.Lock()
	metricsCopy := append([]*prometheus.MetricVec(nil), metricsWithPolicy...)
	metricsWithPolicyMutex.Unlock()
	for _, metric := range metricsCopy {
		// DeletePartialMatch removes all series for the policy regardless of other labels.
		metric.DeletePartialMatch(prometheus.Labels{
			"policy": policyName,
		})
	}
}
