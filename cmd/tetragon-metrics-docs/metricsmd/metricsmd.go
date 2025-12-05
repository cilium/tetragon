// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metricsmd

import (
	"log/slog"

	"github.com/isovalent/metricstool/pkg/metricsmd"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/cobra"
)

type initMetricsFunc func(string, *prometheus.Registry, *slog.Logger) error

func New(targets map[string]string, init initMetricsFunc) *cobra.Command {
	overrides := []metricsmd.LabelOverrides{
		// Theses metrics takes VCS info into account supplied at build
		// time, which changes every build, so override those.
		{
			Metric: "go_info",
			Overrides: []metricsmd.LabelValues{
				{
					Label: "version",
					// renovate: datasource=golang-version
					Values: []string{"go1.25.5"},
				},
			},
		},
		{
			Metric: "tetragon_build_info",
			Overrides: []metricsmd.LabelValues{
				{
					Label:  "commit",
					Values: []string{"931b70f2c9878ba985ba6b589827bea17da6ec33"},
				},
				{
					Label: "go_version",
					// renovate: datasource=golang-version
					Values: []string{"go1.25.5"},
				},
				{
					Label:  "modified",
					Values: []string{"false"},
				},
				{
					Label:  "time",
					Values: []string{"2022-05-13T15:54:45Z"},
				},
				{
					Label:  "version",
					Values: []string{"v1.2.0"},
				},
			},
		},
	}

	config := &metricsmd.Config{
		Targets:        targets,
		LabelOverrides: overrides,
		InitMetrics:    init,
		HeadingLevel:   1,
	}

	cmd, err := metricsmd.NewCmd(nil, nil, config)
	if err != nil {
		slog.Error("failed to create metrics-docs command", "error", err)
	}
	return cmd
}
