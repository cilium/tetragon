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
	"github.com/cilium/tetragon/pkg/metrics/crimetrics"
	"github.com/cilium/tetragon/pkg/metrics/enforcermetrics"
	"github.com/cilium/tetragon/pkg/metrics/errormetrics"
	"github.com/cilium/tetragon/pkg/metrics/eventmetrics"
	"github.com/cilium/tetragon/pkg/metrics/opcodemetrics"
	"github.com/cilium/tetragon/pkg/metrics/overhead"
	"github.com/cilium/tetragon/pkg/metrics/policyfiltermetrics"
	"github.com/cilium/tetragon/pkg/metrics/policymetrics"
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
	eventcache.RegisterMetrics(group)
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
	// process metrics
	process.RegisterMetrics(group)
	// observer ringbuf metrics
	observer.RegisterHealthMetrics(group)
	// watcher metrics
	watchermetrics.RegisterMetrics(group)
	group.ExtendInit(watchermetrics.InitMetrics)
	// observer metrics
	observer.RegisterMetrics(group)
	group.ExtendInit(observer.InitMetrics)
	// tracing metrics
	tracing.RegisterMetrics(group)
	group.ExtendInit(tracing.InitMetrics)
	// exporter metrics
	exporter.RegisterMetrics(group)
	// cgrup rate metrics
	cgroupratemetrics.RegisterMetrics(group)

	// extended metrics, Linux only
	registerHealthMetricsEx(group)

	// policy metrics
	group.MustRegister(policymetrics.NewPolicyCollector())
	// gRPC metrics
	group.MustRegister(grpcmetrics.NewServerMetrics())
	// enforcer metrics
	group.MustRegister(enforcermetrics.NewCollector())
	// overhead metris
	group.MustRegister(overhead.NewBPFCollector())
	// cri metrics
	crimetrics.RegisterMetrics(group)
}
