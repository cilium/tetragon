// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package probemetrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// bpfCollector implements prometheus.Collector. It collects metrics directly from BPF maps.
type bpfCollector struct{}

func NewBPFCollector() prometheus.Collector {
	return &bpfCollector{}
}

func (c *bpfCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- MissedProbes.Desc()
}

func (c *bpfCollector) Collect(ch chan<- prometheus.Metric) {
	lock.Lock()
	defer lock.Unlock()

	for key, stat := range stats {
		ch <- MissedProbes.MustMetric(stat.missed, stat.policy, key.attach)
	}
}
