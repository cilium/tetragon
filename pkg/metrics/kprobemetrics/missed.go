// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package kprobemetrics

import (
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
)

var (
	MissedLink = metrics.MustNewCustomCounter(metrics.NewOpts(
		consts.MetricsNamespace, "", "missed_link_probes_total",
		"The total number of Tetragon probe missed by link.",
		nil, nil, []metrics.UnconstrainedLabel{
			metrics.UnconstrainedLabel{Name: "policy", ExampleValue: "monitor_panic"},
			metrics.UnconstrainedLabel{Name: "attach", ExampleValue: "sys_panic"},
		},
	))

	MissedProg = metrics.MustNewCustomCounter(metrics.NewOpts(
		consts.MetricsNamespace, "", "missed_prog_probes_total",
		"The total number of Tetragon probe missed by program.",
		nil, nil, []metrics.UnconstrainedLabel{
			metrics.UnconstrainedLabel{Name: "policy", ExampleValue: "monitor_panic"},
			metrics.UnconstrainedLabel{Name: "attach", ExampleValue: "sys_panic"},
		},
	))
)
