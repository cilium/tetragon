// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metrics

import (
	"net/http"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const MetricsNamespace = "tetragon"

func EnableMetrics(address string) {
	logger.GetLogger().WithField("addr", address).Info("Starting metrics server")
	http.Handle("/metrics", promhttp.Handler())
	http.ListenAndServe(address, nil)
}
