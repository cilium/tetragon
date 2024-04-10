// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package syscallmetrics

import (
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/cilium/tetragon/pkg/syscallinfo"
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
	registry.MustRegister(syscallStats.ToProm())

	// NOTES:
	// * Delete syscalls_total? It seems to duplicate policy_events_total.
}

func InitMetricsForDocs(registry *prometheus.Registry) {
	InitMetrics(registry)

	// Initialize metrics with example labels
	processLabels := metrics.NewProcessLabels(consts.ExampleNamespace, consts.ExampleWorkload, consts.ExamplePod, consts.ExampleBinary)
	syscallStats.WithLabelValues(processLabels, consts.ExampleSyscallLabel).Inc()
}

func Handle(event interface{}) {
	ev, ok := event.(*tetragon.GetEventsResponse)
	if !ok {
		return
	}

	var syscall string
	var processLabels metrics.ProcessLabels
	if tpEvent := ev.GetProcessTracepoint(); tpEvent != nil {
		if tpEvent.Subsys == "raw_syscalls" && tpEvent.Event == "sys_enter" {
			syscall = rawSyscallName(tpEvent)
			if tpEvent.Process != nil {
				if tpEvent.Process.Pod != nil {
					processLabels.Namespace = tpEvent.Process.Pod.Namespace
					processLabels.Workload = tpEvent.Process.Pod.Workload
					processLabels.Pod = tpEvent.Process.Pod.Name
				}
				processLabels.Binary = tpEvent.Process.Binary
			}
		}
	}

	if syscall != "" {
		syscallStats.WithLabelValues(&processLabels, syscall).Inc()
	}
}

func rawSyscallName(tp *tetragon.ProcessTracepoint) string {
	sysID := int64(-1)
	if len(tp.Args) > 0 && tp.Args[0] != nil {
		if x, ok := tp.Args[0].GetArg().(*tetragon.KprobeArgument_LongArg); ok {
			sysID = x.LongArg
		}
	}
	if sysID == -1 {
		return ""
	}
	return syscallinfo.GetSyscallName(int(sysID))
}
