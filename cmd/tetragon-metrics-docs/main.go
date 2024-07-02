// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"log/slog"
	"os"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/tetragon/cmd/tetragon-metrics-docs/metricsmd"
	"github.com/cilium/tetragon/pkg/metricsconfig"
)

func main() {
	targets := map[string]string{
		"health":    "Tetragon Health",
		"resources": "Tetragon Resources",
		"events":    "Tetragon Events",
	}
	if err := metricsmd.New(targets, initMetrics).Execute(); err != nil {
		os.Exit(1)
	}
}

func initMetrics(target string, reg *prometheus.Registry, _ *slog.Logger) error {
	switch target {
	case "health":
		metricsconfig.EnableHealthMetrics(reg).InitForDocs()
	case "resources":
		metricsconfig.InitResourcesMetricsForDocs(reg)
	case "events":
		metricsconfig.InitEventsMetricsForDocs(reg)
	}
	return nil
}
