// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package javaagent

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
)

const subsystem = "java"

const (
	lostEntry      = "entry"
	lostDefinition = "definition"
)

var (
	ringReceived = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: consts.MetricsNamespace,
		Subsystem: subsystem,
		Name:      "ring_events_received_total",
		Help:      "Number of method entry records Tetragon received from the Java agent rings.",
	})
	ringLost = metrics.MustNewCounter(metrics.NewOpts(
		consts.MetricsNamespace, subsystem,
		"ring_events_lost_total",
		"Number of records the Java agents dropped because their ring was full.",
		nil,
		[]metrics.ConstrainedLabel{{
			Name:   "type",
			Values: []string{lostEntry, lostDefinition},
		}},
		nil,
	), nil)
)

func RegisterHealthMetrics(group metrics.Group) {
	group.MustRegister(ringReceived, ringLost)
}
