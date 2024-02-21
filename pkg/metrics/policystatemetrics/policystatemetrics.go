// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package policystatemetrics

import (
	"context"
	"strings"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/prometheus/client_golang/prometheus"
)

type policyStateCollector struct {
	descriptor    *prometheus.Desc
	sensorManager *sensors.Manager
}

func InitMetrics(registry *prometheus.Registry) {
	registry.MustRegister(newPolicyStateCollector(observer.GetSensorManager()))
}

// This metric collector converts the output of ListTracingPolicies into a few
// gauges metrics on collection. Thus, it needs a sensor manager to query.
func newPolicyStateCollector(sensorManager *sensors.Manager) *policyStateCollector {
	return &policyStateCollector{
		descriptor: prometheus.NewDesc(
			prometheus.BuildFQName(consts.MetricsNamespace, "", "tracingpolicy_loaded"),
			"The number of loaded tracing policy by state.",
			[]string{"state"}, nil,
		),
		sensorManager: sensorManager,
	}
}

func (c *policyStateCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.descriptor
}

func (c *policyStateCollector) Collect(ch chan<- prometheus.Metric) {
	if c.sensorManager == nil {
		logger.GetLogger().Debug("failed retrieving the sensor manager: manager is nil")
		return
	}
	list, err := c.sensorManager.ListTracingPolicies(context.Background())
	if err != nil {
		logger.GetLogger().WithError(err).Warn("error listing tracing policies to collect policies state")
		return
	}

	counters := map[tetragon.TracingPolicyState]int{}
	for _, policy := range list.Policies {
		state := policy.State
		counters[state]++
	}

	ch <- prometheus.MustNewConstMetric(
		c.descriptor,
		prometheus.GaugeValue,
		float64(counters[tetragon.TracingPolicyState_TP_STATE_LOAD_ERROR]),
		strings.TrimPrefix(strings.ToLower(tetragon.TracingPolicyState_TP_STATE_LOAD_ERROR.String()), "tp_state_"),
	)
	ch <- prometheus.MustNewConstMetric(
		c.descriptor,
		prometheus.GaugeValue,
		float64(counters[tetragon.TracingPolicyState_TP_STATE_ERROR]),
		strings.TrimPrefix(strings.ToLower(tetragon.TracingPolicyState_TP_STATE_ERROR.String()), "tp_state_"),
	)
	ch <- prometheus.MustNewConstMetric(
		c.descriptor,
		prometheus.GaugeValue,
		float64(counters[tetragon.TracingPolicyState_TP_STATE_DISABLED]),
		strings.TrimPrefix(strings.ToLower(tetragon.TracingPolicyState_TP_STATE_DISABLED.String()), "tp_state_"),
	)
	ch <- prometheus.MustNewConstMetric(
		c.descriptor,
		prometheus.GaugeValue,
		float64(counters[tetragon.TracingPolicyState_TP_STATE_ENABLED]),
		strings.TrimPrefix(strings.ToLower(tetragon.TracingPolicyState_TP_STATE_ENABLED.String()), "tp_state_"),
	)
}
