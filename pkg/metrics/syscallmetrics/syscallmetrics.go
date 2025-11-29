// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package syscallmetrics

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/cilium/tetragon/pkg/option"
)

var (
	syscallStats = metrics.MustNewGranularCounterWithInit[metrics.ProcessLabels](
		metrics.NewOpts(
			consts.MetricsNamespace, "", "syscalls_total",
			"System calls observed.",
			nil, nil, []metrics.UnconstrainedLabel{{Name: "syscall", ExampleValue: consts.ExampleSyscallLabel}},
		),
		nil,
	)
)

func InitMetrics(registry *prometheus.Registry) {
	registry.MustRegister(syscallStats)

	// NOTES:
	// * Delete syscalls_total? It seems to duplicate policy_events_total.
}

func InitMetricsForDocs(registry *prometheus.Registry) {
	InitMetrics(registry)

	// Initialize metrics with example labels
	processLabels := option.CreateProcessLabels(consts.ExampleNamespace, consts.ExampleWorkload, consts.ExamplePod, consts.ExampleBinary, consts.ExampleNodeName)
	syscallStats.WithLabelValues(processLabels, consts.ExampleSyscallLabel).Inc()
}

func Handle(event any) {
	ev, ok := event.(*tetragon.GetEventsResponse)
	if !ok {
		return
	}

	var syscall string
	var namespace, workload, pod, binary, nodeName string
	if tpEvent := ev.GetProcessTracepoint(); tpEvent != nil {
		if tpEvent.Subsys == "raw_syscalls" && tpEvent.Event == "sys_enter" {
			syscall = rawSyscallName(tpEvent)
			if tpEvent.Process != nil {
				if tpEvent.Process.Pod != nil {
					namespace = tpEvent.Process.Pod.Namespace
					workload = tpEvent.Process.Pod.Workload
					pod = tpEvent.Process.Pod.Name
				}
				binary = tpEvent.Process.Binary
			}
			nodeName = ev.NodeName
		}
	}

	if syscall != "" {
		processLabels := option.CreateProcessLabels(namespace, workload, pod, binary, nodeName)
		syscallStats.WithLabelValues(processLabels, syscall).Inc()
	}
}
