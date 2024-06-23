// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package process

import (
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
)

var ProcessCacheTotal = prometheus.NewGauge(prometheus.GaugeOpts{
	Namespace:   consts.MetricsNamespace,
	Name:        "process_cache_size",
	Help:        "The size of the process cache",
	ConstLabels: nil,
})

type cacheCapacityMetric struct {
	desc *prometheus.Desc
}

func (m *cacheCapacityMetric) Describe(ch chan<- *prometheus.Desc) {
	ch <- m.desc
}

func (m *cacheCapacityMetric) Collect(ch chan<- prometheus.Metric) {
	capacity := 0
	if procCache != nil {
		capacity = procCache.size
	}
	ch <- prometheus.MustNewConstMetric(
		m.desc,
		prometheus.GaugeValue,
		float64(capacity),
	)
}

func NewCacheCollector() prometheus.Collector {
	return &cacheCapacityMetric{
		prometheus.NewDesc(
			prometheus.BuildFQName(consts.MetricsNamespace, "", "process_cache_capacity"),
			"The capacity of the process cache. Expected to be constant.",
			nil, nil,
		),
	}
}

func RegisterMetrics(group metrics.Group) {
	group.MustRegister(ProcessCacheTotal)
	group.MustRegister(NewCacheCollector())
}
