// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package errormetrics

import (
	"fmt"
	"strings"

	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
)

type ErrorType string

var (
	// Process not found on get() call.
	ProcessCacheMissOnGet ErrorType = "process_cache_miss_on_get"
	// Process evicted from the cache.
	ProcessCacheEvicted ErrorType = "process_cache_evicted"
	// Process not found on remove() call.
	ProcessCacheMissOnRemove ErrorType = "process_cache_miss_on_remove"
	// Tid and Pid mismatch that could affect BPF and user space caching logic
	ProcessPidTidMismatch ErrorType = "process_pid_tid_mismatch"
	// An event is missing process info.
	EventMissingProcessInfo ErrorType = "event_missing_process_info"
	// An error occurred in an event handler.
	HandlerError ErrorType = "handler_error"
	// An event finalizer on Process failed
	EventFinalizeProcessInfoFailed ErrorType = "event_finalize_process_info_failed"
)

var (
	ErrorTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "errors_total",
		Help:        "The total number of Tetragon errors. For internal use only.",
		ConstLabels: nil,
	}, []string{"type"})

	HandlerErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "handler_errors_total",
		Help:        "The total number of event handler errors. For internal use only.",
		ConstLabels: nil,
	}, []string{"opcode", "error_type"})
)

func InitMetrics(registry *prometheus.Registry) {
	registry.MustRegister(ErrorTotal)
	registry.MustRegister(HandlerErrors)
}

// Get a new handle on an ErrorTotal metric for an ErrorType
func GetErrorTotal(t ErrorType) prometheus.Counter {
	return ErrorTotal.WithLabelValues(string(t))
}

// Increment an ErrorTotal for an ErrorType
func ErrorTotalInc(t ErrorType) {
	GetErrorTotal(t).Inc()
}

// Get a new handle on the HandlerErrors metric
func GetHandlerErrors(opcode int, err error) prometheus.Counter {
	return HandlerErrors.WithLabelValues(fmt.Sprint(opcode), strings.ReplaceAll(fmt.Sprintf("%T", errors.Cause(err)), "*", ""))
}

// Increment the HandlerErrors metric
func HandlerErrorsInc(opcode int, err error) {
	GetHandlerErrors(opcode, err).Inc()
}
