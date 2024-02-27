// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package policyfiltermetrics

import (
	"fmt"
	"strings"

	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/pkg/errors"
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

var (
	PolicyFilterOpMetrics = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "policyfilter_metrics_total",
		Help:        "Policy filter metrics. For internal use only.",
		ConstLabels: nil,
	}, []string{"subsys", "op", "error_type"})
)

func InitMetrics(registry *prometheus.Registry) {
	registry.MustRegister(PolicyFilterOpMetrics)

	// NOTES:
	// * error, error_type, type - standardize on a label
	// * Don't confuse op in policyfilter_metrics_total with ops.OpCode
	// * Rename policyfilter_metrics_total to get rid of _metrics?
}

func OpInc(subsys Subsys, op Operation, err error) {
	PolicyFilterOpMetrics.WithLabelValues(
		subsys.String(), op.String(),
		strings.ReplaceAll(fmt.Sprintf("%T", errors.Cause(err)), "*", ""),
	).Inc()
}
