// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package errormetrics

import (
	"fmt"

	"github.com/cilium/tetragon/pkg/api/ops"
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
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
	// Failed to resolve Process uid to username
	ProcessMetadataUsernameFailed
	// The username resolution was skipped since the process is not in host
	// namespaces.
	ProcessMetadataUsernameIgnoredNotInHost
)

var errorTypeLabelValues = map[ErrorType]string{
	ProcessCacheMissOnGet:                   "process_cache_miss_on_get",
	ProcessCacheEvicted:                     "process_cache_evicted",
	ProcessCacheMissOnRemove:                "process_cache_miss_on_remove",
	ProcessPidTidMismatch:                   "process_pid_tid_mismatch",
	EventMissingProcessInfo:                 "event_missing_process_info",
	HandlerError:                            "handler_error",
	EventFinalizeProcessInfoFailed:          "event_finalize_process_info_failed",
	ProcessMetadataUsernameFailed:           "process_metadata_username_failed",
	ProcessMetadataUsernameIgnoredNotInHost: "process_metadata_username_ignored_not_in_host_namespaces",
}

func (e ErrorType) String() string {
	return errorTypeLabelValues[e]
}

type EventHandlerError int

// TODO: Recognize different errors returned by individual handlers
const (
	HandlePerfUnknownOp EventHandlerError = iota
	HandlePerfHandlerError
)

var eventHandlerErrorLabelValues = map[EventHandlerError]string{
	HandlePerfUnknownOp:    "unknown_opcode",
	HandlePerfHandlerError: "event_handler_failed",
}

func (e EventHandlerError) String() string {
	return eventHandlerErrorLabelValues[e]
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

func RegisterMetrics(group metrics.Group) {
	group.MustRegister(ErrorTotal)
	group.MustRegister(HandlerErrors)
}

func InitMetrics() {
	// Initialize metrics with labels
	for er := range errorTypeLabelValues {
		GetErrorTotal(er).Add(0)
	}
	for opcode := range ops.OpCodeStrings {
		if opcode != ops.MsgOpUndef && opcode != ops.MsgOpTest {
			GetHandlerErrors(opcode, HandlePerfHandlerError).Add(0)
		}
	}
	// NB: We initialize only ops.MsgOpUndef here, but unknown_opcode can occur for any opcode
	// that is not explicitly handled.
	GetHandlerErrors(ops.MsgOpUndef, HandlePerfUnknownOp).Add(0)
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
func GetHandlerErrors(opcode ops.OpCode, er EventHandlerError) prometheus.Counter {
	return HandlerErrors.WithLabelValues(fmt.Sprint(int32(opcode)), er.String())
}

// Increment the HandlerErrors metric
func HandlerErrorsInc(opcode ops.OpCode, er EventHandlerError) {
	GetHandlerErrors(opcode, er).Inc()
}
