// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package overhead

import (
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
)

var (
	time = metrics.MustNewCustomCounter(metrics.NewOpts(
		consts.MetricsNamespace, "", "overhead_program_seconds_total",
		"The total time of BPF program running.",
		nil, nil, []metrics.UnconstrainedLabel{
			metrics.LabelPolicyNamespace,
			metrics.LabelPolicy,
			{Name: "sensor", ExampleValue: "generic_kprobe"},
			{Name: "attach", ExampleValue: "sys_open"},
			{Name: "section", ExampleValue: "kprobe/sys_open"},
		},
	))

	runs = metrics.MustNewCustomCounter(metrics.NewOpts(
		consts.MetricsNamespace, "", "overhead_program_runs_total",
		"The total number of times BPF program was executed.",
		nil, nil, []metrics.UnconstrainedLabel{
			metrics.LabelPolicyNamespace,
			metrics.LabelPolicy,
			{Name: "sensor", ExampleValue: "generic_kprobe"},
			{Name: "attach", ExampleValue: "sys_open"},
			{Name: "section", ExampleValue: "kprobe/sys_open"},
		},
	))
)
