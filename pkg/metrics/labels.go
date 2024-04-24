// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metrics

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

func NewProcessLabels(namespace, workload, pod, binary string) *ProcessLabels {
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
