// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metrics

import (
	"net/http"
	"strings"

	v1 "github.com/cilium/hubble/pkg/api/v1"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/api/v1/tetragon/codegen/helpers"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/filters"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	readerdns "github.com/cilium/tetragon/pkg/reader/dns"
	"github.com/cilium/tetragon/pkg/reader/exec"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Tetragon debugging and core info metrics
var (
	MsgOpsCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:        consts.MetricNamePrefix + "msg_op_total",
		Help:        "The total number of times we encounter a given message opcode. For internal use only.",
		ConstLabels: nil,
	}, []string{"msg_op"})
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
	ExecveMapSize = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:        consts.MetricNamePrefix + "map_in_use_gauge",
		Help:        "The total number of in-use entries per map.",
		ConstLabels: nil,
	}, []string{"map", "total"})
	LruMapSize = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:        consts.MetricNamePrefix + "lru_in_use_gauge",
		Help:        "The total number of LRU in-use entries.",
		ConstLabels: nil,
	}, []string{"map", "total"})
	EventCacheCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:        consts.MetricNamePrefix + "event_cache",
		Help:        "The total number of Tetragon event cache access/errors. For internal use only.",
		ConstLabels: nil,
	}, []string{"type"})
	RingBufPerfEventReceived = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:        consts.MetricNamePrefix + "ringbuf_perf_event_received",
		Help:        "The total number of Tetragon ringbuf perf events received.",
		ConstLabels: nil,
	}, nil)
	RingBufPerfEventLost = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:        consts.MetricNamePrefix + "ringbuf_perf_event_lost",
		Help:        "The total number of Tetragon ringbuf perf events lost.",
		ConstLabels: nil,
	}, nil)
	RingBufPerfEventErrors = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:        consts.MetricNamePrefix + "ringbuf_perf_event_errors",
		Help:        "The total number of Tetragon ringbuf perf event error count.",
		ConstLabels: nil,
	}, nil)
	ProcessInfoErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:        consts.MetricNamePrefix + "process_info_errors",
		Help:        "The total of times we failed to fetch cached process info for a given event type.",
		ConstLabels: nil,
	}, []string{"event_type"})
	ExecMissingParentErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:        consts.MetricNamePrefix + "exec_missing_parent_errors",
		Help:        "The total of times a given parent exec id could not be found in an exec event.",
		ConstLabels: nil,
	}, []string{"parent_exec_id"})
	SameExecIdErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:        consts.MetricNamePrefix + "exec_parent_child_same_id_errors",
		Help:        "The total of times an error occurs due to a parent and child process have the same exec id.",
		ConstLabels: nil,
	}, []string{"exec_id"})
	GenericKprobeMergeErrors = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:        consts.MetricNamePrefix + "generic_kprobe_merge_errors",
		Help:        "The total number of failed attempts to merge a kprobe and kretprobe event.",
		ConstLabels: nil,
	}, []string{"curr_fn", "curr_type", "prev_fn", "prev_type"})
)

// DNS metrics
var (
	DnsRequestTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: consts.MetricNamePrefix + "dns_total",
		Help: "Dns request/response statistics",
	}, []string{"namespace", "pod", "binary", "names", "rcodes", "response"})
)

func getProcessInfo(process *tetragon.Process) (binary, pod, namespace string) {
	if process != nil {
		binary = process.Binary
		if process.Pod != nil {
			namespace = process.Pod.Namespace
			pod = process.Pod.Name
		}
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

func postDnsMetric(ev *tetragon.GetEventsResponse, res *tetragon.ProcessDns) {
	var rr string

	binary, pod, ns := getProcessInfo(filters.GetProcess(&v1.Event{Event: ev}))

	dns := res.Dns
	names := strings.Join(dns.GetNames(), ",")
	codes := readerdns.GetRCodeString(uint16(dns.GetRcode()))

	if dns.Response {
		rr = "Response"
	} else {
		rr = "Request"
	}

	DnsRequestTotal.WithLabelValues(ns, pod, binary, names, codes, rr).Inc()
}

func handleDnsEvent(processedEvent interface{}) {
	switch ev := processedEvent.(type) {
	case *tetragon.GetEventsResponse:
		switch res := ev.Event.(type) {
		case *tetragon.GetEventsResponse_ProcessDns:
			postDnsMetric(ev, res.ProcessDns)
		}
	}
}

func handleProcessedEvent(processedEvent interface{}) {
	var eventType, namespace, pod, binary string
	switch ev := processedEvent.(type) {
	case *tetragon.GetEventsResponse:
		binary, pod, namespace = getProcessInfo(filters.GetProcess(&v1.Event{Event: ev}))
		var err error
		eventType, err = helpers.EventTypeString(ev.Event)
		if err != nil {
			logger.GetLogger().WithField("event", processedEvent).WithError(err).Warn("metrics: handleProcessedEvent: unhandled event")
			eventType = "unhandled"
		}
	default:
		eventType = "unknown"
	}
	EventsProcessed.WithLabelValues(eventType, namespace, pod, binary).Inc()
}

func ProcessEvent(originalEvent interface{}, processedEvent interface{}) {
	handleOriginalEvent(originalEvent)
	handleProcessedEvent(processedEvent)
	handleDnsEvent(processedEvent)
}

func EnableMetrics(address string) {
	logger.GetLogger().WithField("addr", address).Info("Starting metrics server")
	http.Handle("/metrics", promhttp.Handler())
	http.ListenAndServe(address, nil)
}
