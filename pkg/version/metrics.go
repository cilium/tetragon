// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package version

import (
	"github.com/prometheus/client_golang/prometheus"
)

// buildInfoCollector implements Collector for a Build Information Metric so that the Metric
// collects itself. Add it as an anonymous field to a struct that implements
// Metric, and call init with the Metric itself as an argument.
type buildInfoCollector struct {
	self prometheus.Metric
}

// init provides the buildInfoCollector with a reference to the metric it is supposed
// to collect. It is usually called within the factory function to create a
// metric. See example.
func (b *buildInfoCollector) init(self prometheus.Metric) {
	b.self = self
}

// Describe implements Collector.
func (b *buildInfoCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- b.self.Desc()
}

// Collect implements Collector.
func (b *buildInfoCollector) Collect(ch chan<- prometheus.Metric) {
	ch <- b.self
}

func NewBuildInfoCollector() prometheus.Collector {
	buildInfo := ReadBuildInfo()
	c := &buildInfoCollector{
		prometheus.MustNewConstMetric(
			prometheus.NewDesc(
				"tetragon_build_info",
				"Build information about tetragon",
				nil,
				prometheus.Labels{
					"go_version": buildInfo.GoVersion,
					"commit":     buildInfo.Commit,
					"time":       buildInfo.Time,
					"modified":   buildInfo.Modified,
				},
			),
			prometheus.GaugeValue,
			1),
	}
	c.init(c.self)
	return c
}
