// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metricsconfig

import (
	"sync"

	"github.com/cilium/tetragon/pkg/eventcache"
	"github.com/cilium/tetragon/pkg/exporter"
	"github.com/cilium/tetragon/pkg/grpc/tracing"
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/cgroupratemetrics"
	"github.com/cilium/tetragon/pkg/metrics/errormetrics"
	"github.com/cilium/tetragon/pkg/metrics/eventcachemetrics"
	"github.com/cilium/tetragon/pkg/metrics/eventmetrics"
	"github.com/cilium/tetragon/pkg/metrics/kprobemetrics"
	"github.com/cilium/tetragon/pkg/metrics/opcodemetrics"
	"github.com/cilium/tetragon/pkg/metrics/policyfiltermetrics"
	"github.com/cilium/tetragon/pkg/metrics/policystatemetrics"
	"github.com/cilium/tetragon/pkg/metrics/ratelimitmetrics"
	"github.com/cilium/tetragon/pkg/metrics/ringbufmetrics"
	"github.com/cilium/tetragon/pkg/metrics/ringbufqueuemetrics"
	"github.com/cilium/tetragon/pkg/metrics/watchermetrics"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/version"
	grpcmetrics "github.com/grpc-ecosystem/go-grpc-middleware/providers/prometheus"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	healthMetrics     metrics.Group
	healthMetricsOnce sync.Once
)

func GetHealthGroup() metrics.Group {
	healthMetricsOnce.Do(func() {
		healthMetrics = metrics.NewMetricsGroup(false)
	})
	return healthMetrics
}

func EnableHealthMetrics(registry *prometheus.Registry) metrics.Group {
	healthMetrics := GetHealthGroup()
	registerHealthMetrics(healthMetrics)
	registry.MustRegister(healthMetrics)
	return healthMetrics
}

// NOTE: Health metrics group is marked as constrained. However, the
// constraints are only enforced for metrics implementing CollectorWithInit,
// and custom collectors are responsible for enforcing it on their own. So the
// group's cardinality isn't really constrained until all metrics are migrated
// to the new interface.
func registerHealthMetrics(group metrics.Group) {
	// build info metrics
	group.MustRegister(version.NewBuildInfoCollector())
	// error metrics
	errormetrics.RegisterMetrics(group)
	group.ExtendInit(errormetrics.InitMetrics)
	// event cache metrics
	eventcachemetrics.RegisterMetrics(group)
	group.MustRegister(eventcache.NewCacheCollector())
	group.ExtendInit(eventcachemetrics.InitMetrics)
	// event metrics
	eventmetrics.RegisterHealthMetrics(group)
	group.ExtendInit(eventmetrics.InitHealthMetrics)
	// map metrics
	group.MustRegister(observer.NewBPFCollector())
	// opcode metrics
	opcodemetrics.RegisterMetrics(group)
	group.ExtendInit(opcodemetrics.InitMetrics)
	// policy filter metrics
	policyfiltermetrics.RegisterMetrics(group)
	group.ExtendInit(policyfiltermetrics.InitMetrics)
	// process metrics
	process.RegisterMetrics(group)
	// ringbuf metrics
	ringbufmetrics.RegisterMetrics(group)
	// ringbuf queue metrics
	ringbufqueuemetrics.RegisterMetrics(group)
	// watcher metrics
	watchermetrics.RegisterMetrics(group)
	group.ExtendInit(watchermetrics.InitMetrics)
	// observer metrics
	observer.RegisterMetrics(group)
	group.ExtendInit(observer.InitMetrics)
	// tracing metrics
	tracing.RegisterMetrics(group)
	group.ExtendInit(tracing.InitMetrics)
	// rate limit metrics
	ratelimitmetrics.RegisterMetrics(group)
	// exporter metrics
	exporter.RegisterMetrics(group)
	// cgrup rate metrics
	cgroupratemetrics.RegisterMetrics(group)
	// kprobe metrics
	kprobemetrics.RegisterMetrics(group)
	group.ExtendInitForDocs(kprobemetrics.InitMetricsForDocs)
	// policy state metrics
	group.MustRegister(policystatemetrics.NewPolicyStateCollector())
	// gRPC metrics
	group.MustRegister(grpcmetrics.NewServerMetrics())
	// missed metris
	group.MustRegister(kprobemetrics.NewBPFCollector())
}
