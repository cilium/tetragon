// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metricsconfig

import (
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/cilium/tetragon/pkg/logger"
)

var (
	registry     *prometheus.Registry
	registryOnce sync.Once
)

func GetRegistry() *prometheus.Registry {
	registryOnce.Do(func() {
		registry = prometheus.NewRegistry()
	})
	return registry
}

func EnableMetrics(address string) {
	reg := GetRegistry()

	logger.GetLogger().Info("Starting metrics server", "addr", address)
	http.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg}))
	http.ListenAndServe(address, nil)
}
