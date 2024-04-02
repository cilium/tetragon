// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package policystatemetrics

import (
	"context"
	"strings"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/prometheus/client_golang/prometheus"
)

type policyStateCollector struct {
	descriptor *prometheus.Desc
}

func InitMetrics(registry *prometheus.Registry) {
	registry.MustRegister(newPolicyStateCollector())
}

func InitMetricsForDocs(registry *prometheus.Registry) {
	registry.MustRegister(newPolicyStateZeroCollector())
}

// This metric collector converts the output of ListTracingPolicies into a few
// gauges metrics on collection. Thus, it needs a sensor manager to query.
func newPolicyStateCollector() *policyStateCollector {
	return &policyStateCollector{
		descriptor: prometheus.NewDesc(
			prometheus.BuildFQName(consts.MetricsNamespace, "", "tracingpolicy_loaded"),
			"The number of loaded tracing policy by state.",
			[]string{"state"}, nil,
		),
	}
}

func (c *policyStateCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.descriptor
}

func (c *policyStateCollector) Collect(ch chan<- prometheus.Metric) {

	sm := observer.GetSensorManager()
	if sm == nil {
		logger.GetLogger().Debug("failed retrieving the sensor manager: manager is nil")
		return
	}

	ctx, cancel := context.WithTimeout(context.TODO(), 900*time.Millisecond)
	defer cancel()
	list, err := sm.ListTracingPolicies(ctx)
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

// policyStateZeroCollector implements prometheus.Collector. It collects "zero"
// metrics. It's intended to be used when the sensor manager doesn't exist, but
// we still want Prometheus metrics to be exposed.
type policyStateZeroCollector struct {
	policyStateCollector
}

func newPolicyStateZeroCollector() prometheus.Collector {
	return &policyStateZeroCollector{
		policyStateCollector: *newPolicyStateCollector(),
	}
}

func (c *policyStateZeroCollector) Describe(ch chan<- *prometheus.Desc) {
	c.policyStateCollector.Describe(ch)
}

func (c *policyStateZeroCollector) Collect(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(
		c.descriptor,
		prometheus.GaugeValue,
		0,
		strings.TrimPrefix(strings.ToLower(tetragon.TracingPolicyState_TP_STATE_LOAD_ERROR.String()), "tp_state_"),
	)
	ch <- prometheus.MustNewConstMetric(
		c.descriptor,
		prometheus.GaugeValue,
		0,
		strings.TrimPrefix(strings.ToLower(tetragon.TracingPolicyState_TP_STATE_ERROR.String()), "tp_state_"),
	)
	ch <- prometheus.MustNewConstMetric(
		c.descriptor,
		prometheus.GaugeValue,
		0,
		strings.TrimPrefix(strings.ToLower(tetragon.TracingPolicyState_TP_STATE_DISABLED.String()), "tp_state_"),
	)
	ch <- prometheus.MustNewConstMetric(
		c.descriptor,
		prometheus.GaugeValue,
		0,
		strings.TrimPrefix(strings.ToLower(tetragon.TracingPolicyState_TP_STATE_ENABLED.String()), "tp_state_"),
	)
}
