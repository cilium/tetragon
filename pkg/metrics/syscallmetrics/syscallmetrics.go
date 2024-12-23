// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package syscallmetrics

import (
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	syscallStats = metrics.MustNewGranularCounter[metrics.ProcessLabels](prometheus.CounterOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "syscalls_total",
		Help:        "System calls observed.",
		ConstLabels: nil,
	}, []string{"syscall"})
)

func InitMetrics(registry *prometheus.Registry) {
	registry.MustRegister(syscallStats)

	// NOTES:
	// * Delete syscalls_total? It seems to duplicate policy_events_total.
}

func InitMetricsForDocs(registry *prometheus.Registry) {
	InitMetrics(registry)

	// Initialize metrics with example labels
	processLabels := option.CreateProcessLabels(consts.ExampleNamespace, consts.ExampleWorkload, consts.ExamplePod, consts.ExampleBinary)
	syscallStats.WithLabelValues(processLabels, consts.ExampleSyscallLabel).Inc()
}

func Handle(event interface{}) {
	ev, ok := event.(*tetragon.GetEventsResponse)
	if !ok {
		return
	}

	var syscall string
	var namespace, workload, pod, binary string
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
		}
	}

	if syscall != "" {
		processLabels := option.CreateProcessLabels(namespace, workload, pod, binary)
		syscallStats.WithLabelValues(processLabels, syscall).Inc()
	}
}
