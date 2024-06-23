// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package ratelimitmetrics

import (
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	RateLimitDropped = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "ratelimit_dropped_total",
		Help:        "The total number of rate limit Tetragon drops",
		ConstLabels: nil,
	})
)

func RegisterMetrics(group metrics.Group) {
	group.MustRegister(RateLimitDropped)
}
