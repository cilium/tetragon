// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metricsconfig

import (
	"regexp"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"github.com/cilium/tetragon/pkg/metrics/eventmetrics"
	"github.com/cilium/tetragon/pkg/metrics/syscallmetrics"
)

func initResourcesMetrics(registry *prometheus.Registry) {
	// register common third-party collectors
	registry.MustRegister(collectors.NewGoCollector(
		collectors.WithGoCollectorRuntimeMetrics(
			collectors.GoRuntimeMetricsRule{Matcher: regexp.MustCompile(`^/sched/latencies:seconds`)},
		)))
	registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
}

func initAllResourcesMetrics(registry *prometheus.Registry) {
	initResourcesMetrics(registry)
}

func InitResourcesMetricsForDocs(registry *prometheus.Registry) {
	initResourcesMetrics(registry)
}

func initAllEventsMetrics(registry *prometheus.Registry) {
	eventmetrics.InitEventsMetrics(registry)
	syscallmetrics.InitMetrics(registry)
}

func InitEventsMetricsForDocs(registry *prometheus.Registry) {
	eventmetrics.InitEventsMetricsForDocs(registry)
	syscallmetrics.InitMetricsForDocs(registry)
}

func InitAllMetrics(registry *prometheus.Registry) {
	healthMetrics := EnableHealthMetrics(registry)
	healthMetrics.Init()
	initAllResourcesMetrics(registry)
	initAllEventsMetrics(registry)
}
