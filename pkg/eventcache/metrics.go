// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package eventcache

import (
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
)

type cacheSizeMetric struct {
	desc *prometheus.Desc
}

func (m *cacheSizeMetric) Describe(ch chan<- *prometheus.Desc) {
	ch <- m.desc
}

func (m *cacheSizeMetric) Collect(ch chan<- prometheus.Metric) {
	size := 0
	if cache != nil {
		size = cache.len()
	}
	ch <- prometheus.MustNewConstMetric(
		m.desc,
		prometheus.GaugeValue,
		float64(size),
	)
}

func NewCacheCollector() prometheus.Collector {
	return &cacheSizeMetric{
		prometheus.NewDesc(
			prometheus.BuildFQName(consts.MetricsNamespace, "", "event_cache_entries"),
			"The number of entries in the event cache.",
			nil, nil,
		),
	}
}
