// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package errormetrics

import (
	"maps"
	"slices"
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
)

var errorTypeLabelValues = map[ErrorType]string{
	ProcessPidTidMismatch:          "process_pid_tid_mismatch",
	EventFinalizeProcessInfoFailed: "event_finalize_process_info_failed",
	ProcessMetadataUsernameFailed:  "process_metadata_username_failed",
}

func (e ErrorType) String() string {
	return errorTypeLabelValues[e]
}

type EventHandlerError int

// TODO: Recognize different errors returned by individual handlers
const (
	HandlePerfUnknownOp EventHandlerError = iota
	HandlePerfEmptyData
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
	// Constrained label for error type
	errorTypeLabel = metrics.ConstrainedLabel{
		Name:   "type",
		Values: slices.Collect(maps.Values(errorTypeLabelValues)),
	}
	// Constrained label for opcode (numeric strings)
	opcodeLabel = metrics.ConstrainedLabel{
		Name: "opcode",
		Values: func() []string {
			res := make([]string, 0, len(ops.OpCodeStrings))
			for opcode := range ops.OpCodeStrings {
				if opcode != ops.MSG_OP_TEST {
					// include UNDEF (0) to represent unknown opcodes in docs/metrics
					res = append(res, strconv.Itoa(int(int32(opcode))))
				}
			}
			return res
		}(),
	}
	// Constrained label for handler error type
	handlerErrTypeLabel = metrics.ConstrainedLabel{
		Name:   "error_type",
		Values: slices.Collect(maps.Values(eventHandlerErrorLabelValues)),
	}

	ErrorTotal = metrics.MustNewCounter(
		metrics.NewOpts(
			consts.MetricsNamespace, "", "errors_total",
			"The total number of Tetragon errors. For internal use only.",
			nil, []metrics.ConstrainedLabel{errorTypeLabel}, nil,
		),
		nil,
	)

	HandlerErrors = metrics.MustNewCounter(
		metrics.NewOpts(
			consts.MetricsNamespace, "", "handler_errors_total",
			"The total number of event handler errors. For internal use only.",
			nil, []metrics.ConstrainedLabel{opcodeLabel, handlerErrTypeLabel}, nil,
		),
		nil,
	)
)

// Increment the HandlerErrors metric
func HandlerErrorsInc(opcode ops.OpCode, er EventHandlerError) {
	GetHandlerErrors(opcode, er).Inc()
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

type WarningType int

const (
	// The username resolution was skipped since the process is not in host
	// namespaces.
	ProcessMetadataUsernameIgnoredNotInHost WarningType = iota
)

var warningTypeLabelValues = map[WarningType]string{
	ProcessMetadataUsernameIgnoredNotInHost: "process_metadata_username_ignored_not_in_host_namespaces",
}

func (e WarningType) String() string {
	return warningTypeLabelValues[e]
}

var (
	// Constrained label for warning type
	warningTypeLabel = metrics.ConstrainedLabel{
		Name:   "type",
		Values: slices.Collect(maps.Values(warningTypeLabelValues)),
	}

	WarningTotal = metrics.MustNewCounter(
		metrics.NewOpts(
			consts.MetricsNamespace, "", "warnings_total",
			"The total number of Tetragon warnings. For internal use only.",
			nil, []metrics.ConstrainedLabel{warningTypeLabel}, nil,
		),
		nil,
	)
)

func RegisterMetrics(group metrics.Group) {
	group.MustRegister(ErrorTotal)
	group.MustRegister(HandlerErrors)
	group.MustRegister(WarningTotal)
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

	for er := range warningTypeLabelValues {
		GetWarningTotal(er).Add(0)
	}
}

// Get a new handle on an WarningTotal metric for an WarningType
func GetWarningTotal(er WarningType) prometheus.Counter {
	return WarningTotal.WithLabelValues(er.String())
}

// Increment an WarningTotal for an WarningType
func WarningTotalInc(er WarningType) {
	GetWarningTotal(er).Inc()
}
