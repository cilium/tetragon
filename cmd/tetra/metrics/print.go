// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metrics

import (
	"log/slog"

	"github.com/isovalent/metricstool/pkg/metricsmd"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/cobra"

	"github.com/cilium/tetragon/pkg/metrics/metricsconfig"
)

func New() *cobra.Command {
	targets := map[string]string{
		"tetragon": "Tetragon",
	}

	overrides := []metricsmd.LabelOverrides{
		// Theses metrics takes VCS info into account supplied at build
		// time, which changes every build, so override those.
		{
			Metric: "go_info",
			Overrides: []metricsmd.LabelValues{
				{
					Label:  "version",
					Values: []string{"go1.22.0"},
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
					Label:  "go_version",
					Values: []string{"go1.22.0"},
				},
				{
					Label:  "modified",
					Values: []string{"false"},
				},
				{
					Label:  "time",
					Values: []string{"2022-05-13T15:54:45Z"},
				},
			},
		},
	}

	return metricsmd.NewCmd(nil, nil, map[string]string{}, targets, overrides, initMetrics)
}

func initMetrics(_ string, reg *prometheus.Registry, _ *slog.Logger) error {
	metricsconfig.InitAllMetrics(reg)
	return nil
}
