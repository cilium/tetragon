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
	Namespace string
	Workload  string
	Pod       string
	Binary    string
}

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
		Namespace: namespace,
		Workload:  workload,
		Pod:       pod,
		Binary:    binary,
	}
}

func (l ProcessLabels) Keys() []string {
	return []string{"namespace", "workload", "pod", "binary"}
}

func (l ProcessLabels) Values() []string {
	return []string{l.Namespace, l.Workload, l.Pod, l.Binary}
}
