// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metricsconfig

import (
	"github.com/cilium/tetragon/pkg/metrics/eventmetrics"
	"github.com/cilium/tetragon/pkg/metrics/syscallmetrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

func initResourcesMetrics(registry *prometheus.Registry) {
	// register common third-party collectors
	registry.MustRegister(collectors.NewGoCollector())
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
