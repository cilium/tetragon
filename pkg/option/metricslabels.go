// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package option

import (
	"strings"

	"github.com/cilium/tetragon/pkg/metrics"
)

func DefaultLabelFilter() metrics.LabelFilter {
	return metrics.LabelFilter{
		"namespace": true,
		"workload":  true,
		"pod":       true,
		"binary":    true,
	}
}

func ParseMetricsLabelFilter(labelsString string) []string {
	labels := []string{}
	for _, l := range strings.Split(labelsString, ",") {
		l = strings.TrimSpace(l)
		labels = append(labels, l)
	}
	return labels
}

// CreateProcessLabels creates a new ProcessLabels struct with the global labels
// filter applied. To have a metric respect the labels filter, we have to:
//  1. Define a granular metric with ProcessLabels type parameter (see pkg/metrics/granularmetric.go).
//  2. When calling WithLabelValues, pass a ProcessLabels struct created with CreateProcessLabels.
func CreateProcessLabels(namespace, workload, pod, binary string) *metrics.ProcessLabels {
	if !Config.MetricsLabelFilter["namespace"] {
		namespace = ""
	}
	if !Config.MetricsLabelFilter["workload"] {
		workload = ""
	}
	if !Config.MetricsLabelFilter["pod"] {
		pod = ""
	}
	if !Config.MetricsLabelFilter["binary"] {
		binary = ""
	}
	return metrics.NewProcessLabels(namespace, workload, pod, binary)
}
