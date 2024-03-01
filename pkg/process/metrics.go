// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package process

import (
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
)

var ProcessCacheTotal = prometheus.NewGauge(prometheus.GaugeOpts{
	Namespace:   consts.MetricsNamespace,
	Name:        "process_cache_size",
	Help:        "The size of the process cache",
	ConstLabels: nil,
})

func InitMetrics(registry *prometheus.Registry) {
	registry.MustRegister(ProcessCacheTotal)
}
