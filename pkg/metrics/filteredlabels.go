// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metrics

import (
	"github.com/cilium/tetragon/pkg/option"
)

type FilteredLabels interface {
	Keys() []string
	Values() []string
}

type ProcessLabels struct {
	namespace string
	workload  string
	pod       string
	binary    string
}

// NewProcessLabels creates a new ProcessLabels struct with the global labels
// filter applied. To have a metric respect the labels filter, we have to:
//  1. Define a granular metric with ProcessLabels type parameter (see granularmetric.go).
//  2. When calling WithLabelValues, pass a ProcessLabels struct created with NewProcessLabels.
func NewProcessLabels(namespace, workload, pod, binary string) *ProcessLabels {
	if !option.Config.MetricsLabelFilter["namespace"] {
		namespace = ""
	}
	if !option.Config.MetricsLabelFilter["workload"] {
		workload = ""
	}
	if !option.Config.MetricsLabelFilter["pod"] {
		pod = ""
	}
	if !option.Config.MetricsLabelFilter["binary"] {
		binary = ""
	}
	return &ProcessLabels{
		namespace: namespace,
		workload:  workload,
		pod:       pod,
		binary:    binary,
	}
}

func (l ProcessLabels) Keys() []string {
	return []string{"namespace", "workload", "pod", "binary"}
}

func (l ProcessLabels) Values() []string {
	return []string{l.namespace, l.workload, l.pod, l.binary}
}
