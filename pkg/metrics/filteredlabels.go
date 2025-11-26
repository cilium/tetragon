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

type FilteredLabelsExample interface {
	Example() FilteredLabels
}

type NilLabels struct{}

func (l NilLabels) Keys() []string { return []string{} }

func (l NilLabels) Values() []string { return []string{} }

func (l NilLabels) Example() FilteredLabels { return l }

type ProcessLabels struct {
	Namespace string
	Workload  string
	Pod       string
	Binary    string
	NodeName  string
}

func NewProcessLabels(namespace, workload, pod, binary, nodeName string) *ProcessLabels {
	return &ProcessLabels{
		Namespace: namespace,
		Workload:  workload,
		Pod:       pod,
		Binary:    binary,
		NodeName:  nodeName,
	}
}

func (l ProcessLabels) Keys() []string {
	return []string{"namespace", "workload", "pod", "binary", "node_name"}
}

func (l ProcessLabels) Values() []string {
	return []string{l.Namespace, l.Workload, l.Pod, l.Binary, l.NodeName}
}

func (l ProcessLabels) Example() FilteredLabels {
	l.Namespace = consts.ExampleNamespace
	l.Workload = consts.ExampleWorkload
	l.Pod = consts.ExamplePod
	l.Binary = consts.ExampleBinary
	l.NodeName = consts.ExampleNodeName
	return l
}
