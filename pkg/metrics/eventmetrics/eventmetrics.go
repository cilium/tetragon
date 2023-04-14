// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package eventmetrics

import (
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/api/v1/tetragon/codegen/helpers"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/filters"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/cilium/tetragon/pkg/metrics/errormetrics"
	"github.com/cilium/tetragon/pkg/metrics/syscallmetrics"
	v1 "github.com/cilium/tetragon/pkg/oldhubble/api/v1"
	"github.com/cilium/tetragon/pkg/reader/exec"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	EventsProcessed = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:        consts.MetricNamePrefix + "events_total",
		Help:        "The total number of Tetragon events",
		ConstLabels: nil,
	}, []string{"type", "namespace", "pod", "binary"})
	FlagCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:        consts.MetricNamePrefix + "flags_total",
		Help:        "The total number of Tetragon flags. For internal use only.",
		ConstLabels: nil,
	}, []string{"type"})
	NotifyOverflowedEvents = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:        consts.MetricNamePrefix + "notify_overflowed_events",
		Help:        "The total number of events dropped because listener buffer was full",
		ConstLabels: nil,
	}, nil)

	policyStats = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:        consts.MetricNamePrefix + "policy_stats",
		Help:        "Policy events calls observed.",
		ConstLabels: nil,
	}, []string{"policy", "hook", "namespace", "pod", "binary"})
)

func GetProcessInfo(process *tetragon.Process) (binary, pod, namespace string) {
	if process != nil {
		binary = process.Binary
		if process.Pod != nil {
			namespace = process.Pod.Namespace
			pod = process.Pod.Name
		}
	} else {
		errormetrics.ErrorTotalInc(errormetrics.EventMissingProcessInfo)
	}
	return binary, pod, namespace
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
	var eventType, namespace, pod, binary string
	switch ev := processedEvent.(type) {
	case *tetragon.GetEventsResponse:
		binary, pod, namespace = GetProcessInfo(filters.GetProcess(&v1.Event{Event: ev}))
		var err error
		eventType, err = helpers.ResponseTypeString(ev)
		if err != nil {
			logger.GetLogger().WithField("event", processedEvent).WithError(err).Warn("metrics: handleProcessedEvent: unhandled event")
			eventType = "unhandled"
		}
	default:
		eventType = "unknown"
	}
	EventsProcessed.WithLabelValues(eventType, namespace, pod, binary).Inc()
	if pInfo != nil && pInfo.Name != "" {
		policyStats.
			WithLabelValues(pInfo.Name, pInfo.Hook, namespace, pod, binary).
			Inc()
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
