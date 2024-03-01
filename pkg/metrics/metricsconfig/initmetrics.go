// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metricsconfig

import (
	"github.com/cilium/tetragon/pkg/grpc/tracing"
	"github.com/cilium/tetragon/pkg/metrics/errormetrics"
	"github.com/cilium/tetragon/pkg/metrics/eventcachemetrics"
	"github.com/cilium/tetragon/pkg/metrics/eventmetrics"
	"github.com/cilium/tetragon/pkg/metrics/kprobemetrics"
	"github.com/cilium/tetragon/pkg/metrics/mapmetrics"
	"github.com/cilium/tetragon/pkg/metrics/opcodemetrics"
	"github.com/cilium/tetragon/pkg/metrics/policyfiltermetrics"
	"github.com/cilium/tetragon/pkg/metrics/processexecmetrics"
	"github.com/cilium/tetragon/pkg/metrics/ratelimitmetrics"
	"github.com/cilium/tetragon/pkg/metrics/ringbufmetrics"
	"github.com/cilium/tetragon/pkg/metrics/ringbufqueuemetrics"
	"github.com/cilium/tetragon/pkg/metrics/syscallmetrics"
	"github.com/cilium/tetragon/pkg/metrics/watchermetrics"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/version"
	grpcmetrics "github.com/grpc-ecosystem/go-grpc-middleware/providers/prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

func InitAllMetrics(registry *prometheus.Registry) {
	errormetrics.InitMetrics(registry)
	eventcachemetrics.InitMetrics(registry)
	eventmetrics.InitMetrics(registry)
	kprobemetrics.InitMetrics(registry)
	mapmetrics.InitMetrics(registry)
	opcodemetrics.InitMetrics(registry)
	policyfiltermetrics.InitMetrics(registry)
	processexecmetrics.InitMetrics(registry)
	ringbufmetrics.InitMetrics(registry)
	ringbufqueuemetrics.InitMetrics(registry)
	syscallmetrics.InitMetrics(registry)
	watchermetrics.InitMetrics(registry)
	observer.InitMetrics(registry)
	tracing.InitMetrics(registry)
	ratelimitmetrics.InitMetrics(registry)

	// register BPF collectors
	registry.MustRegister(mapmetrics.NewBPFCollector(
		observer.NewBPFCollector(),
	))
	registry.MustRegister(eventmetrics.NewBPFCollector())

	// register common third-party collectors
	registry.MustRegister(collectors.NewGoCollector())
	registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	registry.MustRegister(grpcmetrics.NewServerMetrics())
	version.InitMetrics(registry)
}
