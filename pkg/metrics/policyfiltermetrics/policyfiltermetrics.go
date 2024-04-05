// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package policyfiltermetrics

import (
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
)

type Subsys int

const (
	RTHooksSubsys Subsys = iota
	PodHandlersSubsys
)

var subsysLabelValues = map[Subsys]string{
	PodHandlersSubsys: "pod-handlers",
	RTHooksSubsys:     "rthooks",
}

func (s Subsys) String() string {
	return subsysLabelValues[s]
}

type Operation int

const (
	AddPodOperation Operation = iota
	UpdatePodOperation
	DeletePodOperation
	AddContainerOperation
)

var operationLabelValues = map[Operation]string{
	AddPodOperation:       "add",
	UpdatePodOperation:    "update",
	DeletePodOperation:    "delete",
	AddContainerOperation: "add-container",
}

func (s Operation) String() string {
	return operationLabelValues[s]
}

type OperationErr int

const (
	NoErr OperationErr = iota
	GenericErr
	PodNamespaceConflictErr
)

var operationErrLabels = map[OperationErr]string{
	NoErr:                   "",
	GenericErr:              "generic-error",
	PodNamespaceConflictErr: "pod-namespace-conflict",
}

func (s OperationErr) String() string {
	return operationErrLabels[s]
}

var (
	PolicyFilterOpMetrics = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "policyfilter_metrics_total",
		Help:        "Policy filter metrics. For internal use only.",
		ConstLabels: nil,
	}, []string{"subsys", "op", "error"})
)

func InitMetrics(registry *prometheus.Registry) {
	registry.MustRegister(PolicyFilterOpMetrics)

	// Initialize metrics with labels
	for _, subsys := range subsysLabelValues {
		for _, op := range operationLabelValues {
			for _, err := range operationErrLabels {
				PolicyFilterOpMetrics.WithLabelValues(
					subsys, op, err,
				).Add(0)
			}
		}
	}

	// NOTES:
	// * Don't confuse op in policyfilter_metrics_total with ops.OpCode
	// * Rename policyfilter_metrics_total to get rid of _metrics?
}

func OpInc(subsys Subsys, op Operation, err string) {
	PolicyFilterOpMetrics.WithLabelValues(subsys.String(), op.String(), err).Inc()
}
