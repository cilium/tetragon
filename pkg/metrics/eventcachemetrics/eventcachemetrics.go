// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package eventcachemetrics

import (
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	processInfoErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:        consts.MetricNamePrefix + "process_info_errors",
		Help:        "The total of times we failed to fetch cached process info for a given event type.",
		ConstLabels: nil,
	}, []string{"event_type"})
)

// Get a new handle on an processInfoErrors metric for an eventType
func ProcessInfoErrorTotal(eventType string) prometheus.Counter {
	return processInfoErrors.WithLabelValues(eventType)
}

// Increment an errorsTotal for an eventType
func ProcessInfoErrorTotalInc(eventType string) {
	ProcessInfoErrorTotal(eventType).Inc()
}
