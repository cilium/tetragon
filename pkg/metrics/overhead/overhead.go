// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package overhead

import (
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
)

var (
	Time = metrics.MustNewCustomCounter(metrics.NewOpts(
		consts.MetricsNamespace, "", "overhead_time_program_total",
		"The total time of BPF program running.",
		nil, nil, []metrics.UnconstrainedLabel{
			metrics.UnconstrainedLabel{Name: "namespace", ExampleValue: "ns"},
			metrics.UnconstrainedLabel{Name: "policy", ExampleValue: "enforce"},
			metrics.UnconstrainedLabel{Name: "sensor", ExampleValue: "generic_kprobe"},
			metrics.UnconstrainedLabel{Name: "attach", ExampleValue: "sys_open"},
		},
	))

	Cnt = metrics.MustNewCustomCounter(metrics.NewOpts(
		consts.MetricsNamespace, "", "overhead_cnt_program_total",
		"The total number of times BPF program was executed.",
		nil, nil, []metrics.UnconstrainedLabel{
			metrics.UnconstrainedLabel{Name: "namespace", ExampleValue: "ns"},
			metrics.UnconstrainedLabel{Name: "policy", ExampleValue: "enforce"},
			metrics.UnconstrainedLabel{Name: "sensor", ExampleValue: "generic_kprobe"},
			metrics.UnconstrainedLabel{Name: "attach", ExampleValue: "sys_open"},
		},
	))
)
