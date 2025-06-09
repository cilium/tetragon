// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package policymetrics

import (
	"context"
	"strings"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/prometheus/client_golang/prometheus"
)

var stateLabel = metrics.ConstrainedLabel{
	Name: "state",
	Values: []string{
		strings.TrimPrefix(strings.ToLower(tetragon.TracingPolicyState_TP_STATE_LOAD_ERROR.String()), "tp_state_"),
		strings.TrimPrefix(strings.ToLower(tetragon.TracingPolicyState_TP_STATE_ERROR.String()), "tp_state_"),
		strings.TrimPrefix(strings.ToLower(tetragon.TracingPolicyState_TP_STATE_DISABLED.String()), "tp_state_"),
		strings.TrimPrefix(strings.ToLower(tetragon.TracingPolicyState_TP_STATE_ENABLED.String()), "tp_state_"),
	},
}

var policyState = metrics.MustNewCustomGauge(metrics.NewOpts(
	consts.MetricsNamespace, "", "tracingpolicy_loaded",
	"The number of loaded tracing policy by state.",
	nil, []metrics.ConstrainedLabel{stateLabel}, nil,
))

var policyKernelMemory = metrics.MustNewCustomGauge(metrics.NewOpts(
	consts.MetricsNamespace, "", "tracingpolicy_kernel_memory_bytes",
	"The amount of kernel memory in bytes used by policy's sensors non-shared BPF maps (memlock).",
	nil, nil, []metrics.UnconstrainedLabel{
		metrics.LabelPolicy,
		metrics.LabelPolicyNamespace,
	},
))

// This metric collector converts the output of ListTracingPolicies into a few
// gauges metrics on collection. Thus, it needs a sensor manager to query.
func NewPolicyCollector() metrics.CollectorWithInit {
	return metrics.NewCustomCollector(
		metrics.CustomMetrics{
			policyState,
			policyKernelMemory,
		},
		collect,
		collectForDocs,
	)
}

func collect(ch chan<- prometheus.Metric) {
	sm := observer.GetSensorManager()
	if sm == nil {
		logger.GetLogger().Debug("failed retrieving the sensor manager: manager is nil")
		return
	}

	ctx, cancel := context.WithTimeout(context.TODO(), 900*time.Millisecond)
	defer cancel()
	list, err := sm.ListTracingPolicies(ctx)
	if err != nil {
		logger.GetLogger().Warn("error listing tracing policies to collect policies state", logfields.Error, err)
		return
	}

	counters := map[tetragon.TracingPolicyState]int{}
	for _, policy := range list.Policies {
		state := policy.State
		counters[state]++
		ch <- policyKernelMemory.MustMetric(float64(policy.KernelMemoryBytes), policy.Name, policy.Namespace)
	}

	ch <- policyState.MustMetric(
		float64(counters[tetragon.TracingPolicyState_TP_STATE_LOAD_ERROR]),
		strings.TrimPrefix(strings.ToLower(tetragon.TracingPolicyState_TP_STATE_LOAD_ERROR.String()), "tp_state_"),
	)
	ch <- policyState.MustMetric(
		float64(counters[tetragon.TracingPolicyState_TP_STATE_ERROR]),
		strings.TrimPrefix(strings.ToLower(tetragon.TracingPolicyState_TP_STATE_ERROR.String()), "tp_state_"),
	)
	ch <- policyState.MustMetric(
		float64(counters[tetragon.TracingPolicyState_TP_STATE_DISABLED]),
		strings.TrimPrefix(strings.ToLower(tetragon.TracingPolicyState_TP_STATE_DISABLED.String()), "tp_state_"),
	)
	ch <- policyState.MustMetric(
		float64(counters[tetragon.TracingPolicyState_TP_STATE_ENABLED]),
		strings.TrimPrefix(strings.ToLower(tetragon.TracingPolicyState_TP_STATE_ENABLED.String()), "tp_state_"),
	)
}

func collectForDocs(ch chan<- prometheus.Metric) {
	for _, state := range stateLabel.Values {
		ch <- policyState.MustMetric(0, state)
	}
	ch <- policyKernelMemory.MustMetric(0, consts.ExamplePolicyLabel, consts.ExampleNamespace)
}
