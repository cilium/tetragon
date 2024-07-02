// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metrics

import (
	"github.com/cilium/tetragon/pkg/metrics/consts"
)

type FilteredLabels interface {
	Keys() []string
	Values() []string
}

// FilteredLabelsWithExamples extends FilteredLabels with a method returning
// example label values, intended to be used when generating documentation.
type FilteredLabelsWithExamples interface {
	FilteredLabels
	ExampleValues() []string
}

type NilLabels struct{}

func (l NilLabels) Keys() []string { return []string{} }

func (l NilLabels) Values() []string { return []string{} }

func (l NilLabels) ExampleValues() []string { return []string{} }

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

func (l ProcessLabels) ExampleValues() []string {
	return []string{consts.ExampleNamespace, consts.ExampleWorkload, consts.ExamplePod, consts.ExampleBinary}
}
