// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metrics

import (
	"net/http"

	"github.com/cilium/tetragon/pkg/grpc/tracing"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics/errormetrics"
	"github.com/cilium/tetragon/pkg/metrics/eventcachemetrics"
	"github.com/cilium/tetragon/pkg/metrics/eventmetrics"
	"github.com/cilium/tetragon/pkg/metrics/kprobemetrics"
	"github.com/cilium/tetragon/pkg/metrics/mapmetrics"
	"github.com/cilium/tetragon/pkg/metrics/opcodemetrics"
	pfmetrics "github.com/cilium/tetragon/pkg/metrics/policyfilter"
	"github.com/cilium/tetragon/pkg/metrics/processexecmetrics"
	"github.com/cilium/tetragon/pkg/metrics/ringbufmetrics"
	"github.com/cilium/tetragon/pkg/metrics/syscallmetrics"
	"github.com/cilium/tetragon/pkg/metrics/watchermetrics"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func InitAllMetrics(registry *prometheus.Registry) {
	errormetrics.InitMetrics(registry)
	eventcachemetrics.InitMetrics(registry)
	eventmetrics.InitMetrics(registry)
	kprobemetrics.InitMetrics(registry)
	mapmetrics.InitMetrics(registry)
	opcodemetrics.InitMetrics(registry)
	pfmetrics.InitMetrics(registry)
	processexecmetrics.InitMetrics(registry)
	ringbufmetrics.InitMetrics(registry)
	syscallmetrics.InitMetrics(registry)
	watchermetrics.InitMetrics(registry)
	observer.InitMetrics(registry)
	tracing.InitMetrics(registry)
}

func EnableMetrics(address string) {
	reg := prometheus.NewRegistry()
	InitAllMetrics(reg)
	logger.GetLogger().WithField("addr", address).Info("Starting metrics server")
	http.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg}))
	http.ListenAndServe(address, nil)
}
