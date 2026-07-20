// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package policymetrics

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/cilium/tetragon/pkg/observer"
)

// policyStates are the states reported by the tracingpolicy_loaded metric.
var policyStates = []tetragon.TracingPolicyState{
	tetragon.TracingPolicyState_TP_STATE_LOAD_ERROR,
	tetragon.TracingPolicyState_TP_STATE_ERROR,
	tetragon.TracingPolicyState_TP_STATE_DISABLED,
	tetragon.TracingPolicyState_TP_STATE_ENABLED,
	tetragon.TracingPolicyState_TP_STATE_SKIPPED,
	tetragon.TracingPolicyState_TP_STATE_PARTIALLY_ENABLED,
}

// policyStateNames is the metric label value of each policyStates entry, in order.
var policyStateNames = func() []string {
	names := make([]string, len(policyStates))
	for i, state := range policyStates {
		names[i] = strings.TrimPrefix(strings.ToLower(state.String()), "tp_state_")
	}
	return names
}()

var stateLabel = metrics.ConstrainedLabel{
	Name:   "state",
	Values: policyStateNames,
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

var selectorActions = metrics.MustNewCustomCounter(metrics.NewOpts(
	consts.MetricsNamespace, "", "tracingpolicy_selector_actions_total",
	"The total number of tracing policy actions observed per selector.",
	nil, nil, []metrics.UnconstrainedLabel{
		metrics.LabelPolicy,
		metrics.LabelPolicyNamespace,
		{Name: "hook", ExampleValue: consts.ExampleKprobeLabel},
		{Name: "hook_index", ExampleValue: "0"},
		{Name: "selector_index", ExampleValue: "0"},
		{Name: "selector_label", ExampleValue: "example-selector"},
		{Name: "action", ExampleValue: "post"},
	},
))

// This metric collector converts the output of ListTracingPolicies into a few
// gauges metrics on collection. Thus, it needs a sensor manager to query.
func NewPolicyCollector() metrics.CollectorWithInit {
	return metrics.NewCustomCollector(
		metrics.CustomMetrics{
			policyState,
			policyKernelMemory,
			selectorActions,
		},
		collect,
		collectForDocs,
	)
}

type actionCounterValue struct {
	action string
	count  uint64
}

var policyActionNames = []string{
	"post",
	"signal",
	"monitor_signal",
	"override",
	"monitor_override",
	"notify_enforcer",
	"monitor_notify_enforcer",
	"set",
	"monitor_set",
	"nopost",
}

func actionCounterValues(counters *tetragon.TracingPolicyActionCounters) []actionCounterValue {
	if counters == nil {
		return nil
	}
	return []actionCounterValue{
		{action: "post", count: counters.GetPost()},
		{action: "signal", count: counters.GetSignal()},
		{action: "monitor_signal", count: counters.GetMonitorSignal()},
		{action: "override", count: counters.GetOverride()},
		{action: "monitor_override", count: counters.GetMonitorOverride()},
		{action: "notify_enforcer", count: counters.GetNotifyEnforcer()},
		{action: "monitor_notify_enforcer", count: counters.GetMonitorNotifyEnforcer()},
		{action: "set", count: counters.GetSet()},
		{action: "monitor_set", count: counters.GetMonitorSet()},
		{action: "nopost", count: counters.GetNopost()},
	}
}

func collect(ch chan<- prometheus.Metric) {
	sm := observer.GetSensorManager()
	if sm == nil {
		logger.GetLogger().Debug("failed retrieving the sensor manager: manager is nil")
		return
	}

	ctx, cancel := context.WithTimeout(context.TODO(), 900*time.Millisecond)
	defer cancel()
	list, err := sm.ListTracingPolicies(ctx, "")
	if err != nil {
		logger.GetLogger().Warn("error listing tracing policies to collect policies state", logfields.Error, err)
		return
	}

	counters := map[tetragon.TracingPolicyState]int{}
	for _, policy := range list.Policies {
		state := policy.State
		counters[state]++
		ch <- policyKernelMemory.MustMetric(float64(policy.KernelMemoryBytes), policy.Name, policy.Namespace)
		collectSelectorActions(ch, policy)
	}

	for i, state := range policyStates {
		ch <- policyState.MustMetric(float64(counters[state]), policyStateNames[i])
	}
}

func collectSelectorActions(ch chan<- prometheus.Metric, policy *tetragon.TracingPolicyStatus) {
	for _, selector := range policy.GetStats().GetSelectorActionCounters() {
		selectorIndex := strconv.FormatUint(uint64(selector.GetSelectorIndex().Value), 10)
		hookIndex := strconv.FormatUint(uint64(selector.GetHookIndex().Value), 10)
		for _, counter := range actionCounterValues(selector.GetActionCounters()) {
			if counter.count == 0 {
				continue
			}
			ch <- selectorActions.MustMetric(
				float64(counter.count),
				policy.Name,
				policy.Namespace,
				selector.GetHook(),
				hookIndex,
				selectorIndex,
				selector.GetSelectorLabel(),
				counter.action,
			)
		}
	}
}

func collectForDocs(ch chan<- prometheus.Metric) {
	for _, state := range stateLabel.Values {
		ch <- policyState.MustMetric(0, state)
	}
	ch <- policyKernelMemory.MustMetric(0, consts.ExamplePolicyLabel, consts.ExampleNamespace)
	for _, action := range policyActionNames {
		ch <- selectorActions.MustMetric(
			0,
			consts.ExamplePolicyLabel,
			consts.ExampleNamespace,
			consts.ExampleKprobeLabel,
			"0",
			"0",
			"example-selector",
			action,
		)
	}
}
