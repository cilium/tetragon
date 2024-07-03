// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metrics

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
