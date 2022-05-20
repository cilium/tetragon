// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metrics

import (
	"net/http"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Tetragon debugging and core info metrics
var (
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

func EnableMetrics(address string) {
	logger.GetLogger().WithField("addr", address).Info("Starting metrics server")
	http.Handle("/metrics", promhttp.Handler())
	http.ListenAndServe(address, nil)
}
