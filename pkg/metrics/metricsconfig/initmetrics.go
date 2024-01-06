// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metricsconfig

import (
	"github.com/cilium/tetragon/pkg/eventcache"
	"github.com/cilium/tetragon/pkg/exporter"
	"github.com/cilium/tetragon/pkg/grpc/tracing"
	"github.com/cilium/tetragon/pkg/metrics/cgroupratemetrics"
	"github.com/cilium/tetragon/pkg/metrics/errormetrics"
	"github.com/cilium/tetragon/pkg/metrics/eventcachemetrics"
	"github.com/cilium/tetragon/pkg/metrics/eventmetrics"
	"github.com/cilium/tetragon/pkg/metrics/kprobemetrics"
	"github.com/cilium/tetragon/pkg/metrics/mapmetrics"
	"github.com/cilium/tetragon/pkg/metrics/opcodemetrics"
	"github.com/cilium/tetragon/pkg/metrics/policyfiltermetrics"
	"github.com/cilium/tetragon/pkg/metrics/policystatemetrics"
	"github.com/cilium/tetragon/pkg/metrics/ratelimitmetrics"
	"github.com/cilium/tetragon/pkg/metrics/ringbufmetrics"
	"github.com/cilium/tetragon/pkg/metrics/ringbufqueuemetrics"
	"github.com/cilium/tetragon/pkg/metrics/syscallmetrics"
	"github.com/cilium/tetragon/pkg/metrics/watchermetrics"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/version"
	grpcmetrics "github.com/grpc-ecosystem/go-grpc-middleware/providers/prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

func initHealthMetrics(registry *prometheus.Registry) {
	version.InitMetrics(registry)
	errormetrics.InitMetrics(registry)
	eventcachemetrics.InitMetrics(registry)
	registry.MustRegister(eventcache.NewCacheCollector())
	eventmetrics.InitHealthMetrics(registry)
	mapmetrics.InitMetrics(registry)
	opcodemetrics.InitMetrics(registry)
	policyfiltermetrics.InitMetrics(registry)
	process.InitMetrics(registry)
	ringbufmetrics.InitMetrics(registry)
	ringbufqueuemetrics.InitMetrics(registry)
	watchermetrics.InitMetrics(registry)
	observer.InitMetrics(registry)
	tracing.InitMetrics(registry)
	ratelimitmetrics.InitMetrics(registry)
	exporter.InitMetrics(registry)
	cgroupratemetrics.InitMetrics(registry)

	// register common third-party collectors
	registry.MustRegister(grpcmetrics.NewServerMetrics())
}

func initAllHealthMetrics(registry *prometheus.Registry) {
	initHealthMetrics(registry)

	kprobemetrics.InitMetrics(registry)
	policystatemetrics.InitMetrics(registry)

	// register custom collectors
	registry.MustRegister(observer.NewBPFCollector())
	registry.MustRegister(eventmetrics.NewBPFCollector())
	registry.MustRegister(kprobemetrics.NewBPFCollector())
}

func InitHealthMetricsForDocs(registry *prometheus.Registry) {
	initHealthMetrics(registry)

	kprobemetrics.InitMetricsForDocs(registry)
	policystatemetrics.InitMetricsForDocs(registry)

	// register custom zero collectors
	registry.MustRegister(observer.NewBPFZeroCollector())
	registry.MustRegister(eventmetrics.NewBPFZeroCollector())
	registry.MustRegister(kprobemetrics.NewBPFZeroCollector())
}

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
	initAllHealthMetrics(registry)
	initAllResourcesMetrics(registry)
	initAllEventsMetrics(registry)
}
