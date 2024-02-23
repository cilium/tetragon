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

type ErrorType int

const (
	// Process not found on get() call.
	ProcessCacheMissOnGet ErrorType = iota
	// Process evicted from the cache.
	ProcessCacheEvicted
	// Process not found on remove() call.
	ProcessCacheMissOnRemove
	// Tid and Pid mismatch that could affect BPF and user space caching logic
	ProcessPidTidMismatch
	// An event is missing process info.
	EventMissingProcessInfo
	// An error occurred in an event handler.
	HandlerError
	// An event finalizer on Process failed
	EventFinalizeProcessInfoFailed
)

var errorTypeLabelValues = map[ErrorType]string{
	ProcessCacheMissOnGet:          "process_cache_miss_on_get",
	ProcessCacheEvicted:            "process_cache_evicted",
	ProcessCacheMissOnRemove:       "process_cache_miss_on_remove",
	ProcessPidTidMismatch:          "process_pid_tid_mismatch",
	EventMissingProcessInfo:        "event_missing_process_info",
	HandlerError:                   "handler_error",
	EventFinalizeProcessInfoFailed: "event_finalize_process_info_failed",
}

func (e ErrorType) String() string {
	return errorTypeLabelValues[e]
}

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

	// NOTES:
	// * op, msg_op, opcode - standardize on a label (+ add human-readable label)
	// * error, error_type, type - standardize on a label
	// * Delete errors_total{type="handler_error"} - it duplicates handler_errors_total
	// * Consider further splitting errors_total
	// * Rename handler_errors_total to event_handler_errors_total?
}

// Get a new handle on an ErrorTotal metric for an ErrorType
func GetErrorTotal(er ErrorType) prometheus.Counter {
	return ErrorTotal.WithLabelValues(er.String())
}

// Increment an ErrorTotal for an ErrorType
func ErrorTotalInc(er ErrorType) {
	GetErrorTotal(er).Inc()
}

// Get a new handle on the HandlerErrors metric
func GetHandlerErrors(opcode int, err error) prometheus.Counter {
	return HandlerErrors.WithLabelValues(fmt.Sprint(opcode), strings.ReplaceAll(fmt.Sprintf("%T", errors.Cause(err)), "*", ""))
}

// Increment the HandlerErrors metric
func HandlerErrorsInc(opcode int, err error) {
	GetHandlerErrors(opcode, err).Inc()
}
