// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
	readerdns "github.com/cilium/tetragon/pkg/reader/dns"
	"github.com/cilium/tetragon/pkg/reader/exec"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type ErrorType string

const (
	// Parent process was not found in the pid map for a process without the clone flag.
	NoParentNoClone ErrorType = "no_parent_no_clone"
	// Process not found on get() call.
	ProcessCacheMissOnGet ErrorType = "process_cache_miss_on_get"
	// Process evicted from the cache.
	ProcessCacheEvicted ErrorType = "process_cache_evicted"
	// Process not found on remove() call.
	ProcessCacheMissOnRemove ErrorType = "process_cache_miss_on_remove"
	// Missing event handler.
	UnhandledEvent ErrorType = "unhandled_event"
	// Event cache add network entry to cache.
	EventCacheNetworkCount ErrorType = "event_cache_network_count"
	// Event cache add process entry to cache.
	EventCacheProcessCount ErrorType = "event_cache_process_count"
	// Event cache podInfo retries failed.
	EventCachePodInfoRetryFailed ErrorType = "event_cache_podinfo_retry_failed"
	// Event cache endpoint retries failed.
	EventCacheEndpointRetryFailed ErrorType = "event_cache_endpoint_retry_failed"
	// Event cache failed to set process information for an event.
	EventCacheProcessInfoFailed ErrorType = "event_cache_process_info_failed"
	// There was an invalid entry in the pid map.
	PidMapInvalidEntry ErrorType = "pid_map_invalid_entry"
	// An entry was evicted from the pid map because the map was full.
	PidMapEvicted ErrorType = "pid_map_evicted"
	// PID not found in the pid map on remove() call.
	PidMapMissOnRemove ErrorType = "pid_map_miss_on_remove"
	// An exec event without parent info.
	ExecMissingParent ErrorType = "exec_missing_parent"
	// MetricNamePrefix defines the prefix for Prometheus metrics.
	MetricNamePrefix string = "isovalent_"
)

// TETRAGON debugging and core info metrics
var (
	MsgOpsCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:        MetricNamePrefix + "msg_op_total",
		Help:        "The total number of times we encounter a given message opcode. For internal use only.",
		ConstLabels: nil,
	}, []string{"msg_op"})
	EventsProcessed = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:        MetricNamePrefix + "events_total",
		Help:        "The total number of TETRAGON events",
		ConstLabels: nil,
	}, []string{"type", "namespace", "pod", "binary"})
	FlagCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:        MetricNamePrefix + "flags_total",
		Help:        "The total number of TETRAGON flags. For internal use only.",
		ConstLabels: nil,
	}, []string{"type"})
	ErrorCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:        MetricNamePrefix + "errors_total",
		Help:        "The total number of TETRAGON errors. For internal use only.",
		ConstLabels: nil,
	}, []string{"type"})
	ExecveMapSize = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:        MetricNamePrefix + "map_in_use_gauge",
		Help:        "The total number of in-use entries per map.",
		ConstLabels: nil,
	}, []string{"map", "total"})
	LruMapSize = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:        MetricNamePrefix + "lru_in_use_gauge",
		Help:        "The total number of LRU in-use entries.",
		ConstLabels: nil,
	}, []string{"map", "total"})
	EventCacheCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:        MetricNamePrefix + "event_cache",
		Help:        "The total number of TETRAGON event cache access/errors. For internal use only.",
		ConstLabels: nil,
	}, []string{"type"})
	RingBufPerfEventReceived = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:        MetricNamePrefix + "ringbuf_perf_event_received",
		Help:        "The total number of TETRAGON ringbuf perf events received.",
		ConstLabels: nil,
	}, nil)
	RingBufPerfEventLost = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:        MetricNamePrefix + "ringbuf_perf_event_lost",
		Help:        "The total number of TETRAGON ringbuf perf events lost.",
		ConstLabels: nil,
	}, nil)
	RingBufPerfEventErrors = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:        MetricNamePrefix + "ringbuf_perf_event_errors",
		Help:        "The total number of TETRAGON ringbuf perf event error count.",
		ConstLabels: nil,
	}, nil)
	ProcessInfoErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:        MetricNamePrefix + "process_info_errors",
		Help:        "The total of times we failed to fetch cached process info for a given event type.",
		ConstLabels: nil,
	}, []string{"event_type"})
	ExecMissingParentErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:        MetricNamePrefix + "exec_missing_parent_errors",
		Help:        "The total of times a given parent exec id could not be found in an exec event.",
		ConstLabels: nil,
	}, []string{"parent_exec_id"})
)

// DNS metrics
var (
	DnsRequestTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: MetricNamePrefix + "dns_total",
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
