// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package errormetrics

import (
	"maps"
	"slices"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
)

type DebugType int

const (
	// The username resolution was skipped since the process is not in host
	// namespaces.
	ProcessMetadataUsernameIgnoredNotInHost DebugType = iota
)

var debugTypeLabelValues = map[DebugType]string{
	ProcessMetadataUsernameIgnoredNotInHost: "process_metadata_username_ignored_not_in_host_namespaces",
}

func (e DebugType) String() string {
	return debugTypeLabelValues[e]
}

var (
	// Constrained label for debug type
	debugTypeLabel = metrics.ConstrainedLabel{
		Name:   "type",
		Values: slices.Collect(maps.Values(debugTypeLabelValues)),
	}

	DebugTotal = metrics.MustNewCounter(
		metrics.NewOpts(
			consts.MetricsNamespace, "", "debug_events_total",
			"The total number of Tetragon debug events. For internal use only.",
			nil, []metrics.ConstrainedLabel{debugTypeLabel}, nil,
		),
		nil,
	)
)

// Get a new handle on a DebugTotal metric for a DebugType
func GetDebugTotal(er DebugType) prometheus.Counter {
	return DebugTotal.WithLabelValues(er.String())
}

// Increment a DebugTotal for a DebugType
func DebugTotalInc(er DebugType) {
	GetDebugTotal(er).Inc()
}
