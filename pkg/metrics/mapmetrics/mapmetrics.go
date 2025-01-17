// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package mapmetrics

import (
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
)

var MapLabel = metrics.ConstrainedLabel{
	Name: "map",
	// These are maps which usage we monitor, not maps from which we read
	// metrics. Metrics are read from separate maps suffixed with "_stats".
	Values: []string{"execve_map", "tg_execve_joined_info_map"},
}

var (
	MapSize = metrics.MustNewCustomGauge(metrics.NewOpts(
		consts.MetricsNamespace, "", "map_entries",
		"The total number of in-use entries per map.",
		nil, []metrics.ConstrainedLabel{MapLabel}, nil,
	))
	MapCapacity = metrics.MustNewCustomGauge(metrics.NewOpts(
		consts.MetricsNamespace, "", "map_capacity",
		"Capacity of a BPF map. Expected to be constant.",
		nil, []metrics.ConstrainedLabel{MapLabel}, nil,
	))
	MapErrorsUpdate = metrics.MustNewCustomGauge(metrics.NewOpts(
		consts.MetricsNamespace, "", "map_errors_update_total",
		"The number of failed updates per map.",
		nil, []metrics.ConstrainedLabel{MapLabel}, nil,
	))
	MapErrorsDelete = metrics.MustNewCustomGauge(metrics.NewOpts(
		consts.MetricsNamespace, "", "map_errors_delete_total",
		"The number of failed deletes per map.",
		nil, []metrics.ConstrainedLabel{MapLabel}, nil,
	))
)
