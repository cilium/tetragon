// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package errormetrics

import (
	"strconv"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/tetragon/pkg/api/ops"
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
)

type ErrorType int

const (
	// Tid and Pid mismatch that could affect BPF and user space caching logic
	ProcessPidTidMismatch ErrorType = iota
	// An event finalizer on Process failed
	EventFinalizeProcessInfoFailed
	// Failed to resolve Process uid to username
	ProcessMetadataUsernameFailed
	// The username resolution was skipped since the process is not in host
	// namespaces.
	ProcessMetadataUsernameIgnoredNotInHost
)

var errorTypeLabelValues = map[ErrorType]string{
	ProcessPidTidMismatch:                   "process_pid_tid_mismatch",
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
		if opcode != ops.MSG_OP_UNDEF && opcode != ops.MSG_OP_TEST {
			GetHandlerErrors(opcode, HandlePerfHandlerError).Add(0)
		}
	}
	// NB: We initialize only ops.MSG_OP_UNDEF here, but unknown_opcode can occur for any opcode
	// that is not explicitly handled.
	GetHandlerErrors(ops.MSG_OP_UNDEF, HandlePerfUnknownOp).Add(0)
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
	return HandlerErrors.WithLabelValues(strconv.Itoa(int(int32(opcode))), er.String())
}

// Increment the HandlerErrors metric
func HandlerErrorsInc(opcode ops.OpCode, er EventHandlerError) {
	GetHandlerErrors(opcode, er).Inc()
}
