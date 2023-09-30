// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package process

import (
	"fmt"

	"github.com/cilium/tetragon/pkg/metrics/mapmetrics"
	"github.com/prometheus/client_golang/prometheus"
)

// bpfCollector implements prometheus.Collector. It collects metrics directly from BPF maps.
type bpfCollector struct{}

func NewBPFCollector() prometheus.Collector {
	return &bpfCollector{}
}

func (c *bpfCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- mapmetrics.MapSize.Desc()
}

func (c *bpfCollector) Collect(ch chan<- prometheus.Metric) {
	if procCache != nil {
		ch <- mapmetrics.MapSize.MustMetric(
			float64(procCache.len()),
			"processLru", fmt.Sprint(procCache.size),
		)
	}
}
