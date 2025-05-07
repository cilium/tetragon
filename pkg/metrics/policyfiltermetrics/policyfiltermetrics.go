// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package policyfiltermetrics

import (
	"maps"
	"slices"

	"github.com/cilium/tetragon/pkg/metrics"
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
	subsysLabel = metrics.ConstrainedLabel{
		Name:   "subsys",
		Values: slices.Collect(maps.Values(subsysLabelValues)),
	}

	operationLabel = metrics.ConstrainedLabel{
		Name:   "operation",
		Values: slices.Collect(maps.Values(operationLabelValues)),
	}

	errorLabel = metrics.ConstrainedLabel{
		Name:   "error",
		Values: slices.Collect(maps.Values(operationErrLabels)),
	}
)

var (
	PolicyFilterOpMetrics = metrics.MustNewCounter(metrics.NewOpts(
		consts.MetricsNamespace, "", "policyfilter_operations_total",
		"Number of policy filter operations.",
		nil, []metrics.ConstrainedLabel{subsysLabel, operationLabel, errorLabel}, nil,
	), nil)

	PolicyFilterHookContainerNameMissingMetrics = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "policyfilter_hook_container_name_missing_total",
		Help:        "The total number of operations when the container name was missing in the OCI hook",
		ConstLabels: nil,
	})

	PolicyFilterHookContainerImageMissingMetrics = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "policyfilter_hook_container_image_missing_total",
		Help:        "The total number of operations when the container image was missing in the OCI hook",
		ConstLabels: nil,
	})
)

func RegisterMetrics(group metrics.Group) {
	group.MustRegister(PolicyFilterOpMetrics, PolicyFilterHookContainerNameMissingMetrics, PolicyFilterHookContainerImageMissingMetrics)
}

func OpInc(subsys Subsys, op Operation, err string) {
	PolicyFilterOpMetrics.WithLabelValues(subsys.String(), op.String(), err).Inc()
}

func ContNameMissInc() {
	PolicyFilterHookContainerNameMissingMetrics.Inc()
}

func ContImageMissInc() {
	PolicyFilterHookContainerImageMissingMetrics.Inc()
}
