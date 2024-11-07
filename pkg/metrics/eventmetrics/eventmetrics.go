// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package eventmetrics

import (
	"maps"
	"slices"

	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/api/v1/tetragon/codegen/helpers"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/filters"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/cilium/tetragon/pkg/metrics/syscallmetrics"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/exec"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	perfEventErrors = map[int]string{
		processapi.SentFailedUnknown: "unknown",
		processapi.SentFailedEnoent:  "ENOENT",
		processapi.SentFailedE2big:   "E2BIG",
		processapi.SentFailedEbusy:   "EBUSY",
		processapi.SentFailedEinval:  "EINVAL",
		processapi.SentFailedEnospc:  "ENOSPC",
	}
	perfEventErrorLabel = metrics.ConstrainedLabel{
		Name:   "error",
		Values: slices.Collect(maps.Values(perfEventErrors)),
	}
)

var (
	EventsProcessed = metrics.MustNewGranularCounter[metrics.ProcessLabels](prometheus.CounterOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "events_total",
		Help:        "The total number of Tetragon events",
		ConstLabels: nil,
	}, []string{"type"})
	MissedEvents = metrics.MustNewCustomCounter(metrics.NewOpts(
		consts.MetricsNamespace, "bpf", "missed_events_total",
		"Number of Tetragon perf events that are failed to be sent from the kernel.",
		nil, []metrics.ConstrainedLabel{metrics.OpCodeLabel, perfEventErrorLabel}, nil,
	))
	FlagCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "flags_total",
		Help:        "The total number of Tetragon flags. For internal use only.",
		ConstLabels: nil,
	}, []string{"type"})
	NotifyOverflowedEvents = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "notify_overflowed_events_total",
		Help:        "The total number of events dropped because listener buffer was full",
		ConstLabels: nil,
	})

	policyStats = metrics.MustNewGranularCounter[metrics.ProcessLabels](prometheus.CounterOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "policy_events_total",
		Help:        "Policy events calls observed.",
		ConstLabels: nil,
	}, []string{"policy", "hook"})

	missingProcessInfo = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: consts.MetricsNamespace,
		Name:      "events_missing_process_info_total",
		Help:      "Number of events missing process info.",
	})
)

func RegisterHealthMetrics(group metrics.Group) {
	group.MustRegister(
		FlagCount,
		NotifyOverflowedEvents,
		NewBPFCollector(),
		missingProcessInfo,
	)
}

func InitHealthMetrics() {
	// Initialize metrics with labels
	for _, v := range exec.FlagStrings {
		FlagCount.WithLabelValues(v).Add(0)
	}
}

func InitEventsMetrics(registry *prometheus.Registry) {
	registry.MustRegister(EventsProcessed)
	registry.MustRegister(policyStats)
}

func InitEventsMetricsForDocs(registry *prometheus.Registry) {
	InitEventsMetrics(registry)

	// Initialize metrics with example labels
	processLabels := option.CreateProcessLabels(consts.ExampleNamespace, consts.ExampleWorkload, consts.ExamplePod, consts.ExampleBinary)
	for ev, evString := range tetragon.EventType_name {
		if tetragon.EventType(ev) != tetragon.EventType_UNDEF && tetragon.EventType(ev) != tetragon.EventType_TEST {
			EventsProcessed.WithLabelValues(processLabels, evString).Add(0)
		}
	}
	policyStats.WithLabelValues(processLabels, consts.ExamplePolicyLabel, consts.ExampleKprobeLabel).Add(0)
}

func GetProcessInfo(process *tetragon.Process) (binary, pod, workload, namespace string) {
	if process != nil {
		binary = process.Binary
		if process.Pod != nil {
			namespace = process.Pod.Namespace
			workload = process.Pod.Workload
			pod = process.Pod.Name
		}
	} else {
		missingProcessInfo.Inc()
	}
	return binary, pod, workload, namespace
}

func handleOriginalEvent(originalEvent interface{}) {
	var flags uint32
	switch msg := originalEvent.(type) {
	case *processapi.MsgExecveEventUnix:
		flags = msg.Process.Flags
	}
	for _, flag := range exec.DecodeCommonFlags(flags) {
		FlagCount.WithLabelValues(flag).Inc()
	}
}

func handleProcessedEvent(pInfo *tracingpolicy.PolicyInfo, processedEvent interface{}) {
	var eventType, namespace, workload, pod, binary string
	switch ev := processedEvent.(type) {
	case *tetragon.GetEventsResponse:
		binary, pod, workload, namespace = GetProcessInfo(filters.GetProcess(&v1.Event{Event: ev}))
		var err error
		eventType, err = helpers.ResponseTypeString(ev)
		if err != nil {
			logger.GetLogger().WithField("event", processedEvent).WithError(err).Warn("metrics: handleProcessedEvent: unhandled event")
			eventType = "unhandled"
		}
	default:
		eventType = "unknown"
	}
	processLabels := option.CreateProcessLabels(namespace, workload, pod, binary)
	EventsProcessed.WithLabelValues(processLabels, eventType).Inc()
	if pInfo != nil && pInfo.Name != "" {
		policyStats.
			WithLabelValues(processLabels, pInfo.Name, pInfo.Hook).Inc()
	}
}

func ProcessEvent(originalEvent interface{}, processedEvent interface{}) {
	handleOriginalEvent(originalEvent)

	var policyInfo tracingpolicy.PolicyInfo
	if policyEv, ok := originalEvent.(tracingpolicy.PolicyEvent); ok {
		policyInfo = policyEv.PolicyInfo()
	}

	handleProcessedEvent(&policyInfo, processedEvent)
	syscallmetrics.Handle(processedEvent)
}
