// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package cgroupratemetrics

import (
	"maps"
	"slices"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
)

type CgroupRateType int

const (
	ThrottleStart CgroupRateType = iota
	ThrottleStop
	LookupFail
	UpdateFail
	DeleteFail
	Check
	Process
	Delete
)

var totalLabelValues = map[CgroupRateType]string{
	ThrottleStart: "throttle_start",
	ThrottleStop:  "throttle_stop",
	LookupFail:    "lookup_fail",
	UpdateFail:    "update_fail",
	DeleteFail:    "delete_fail",
	Check:         "check",
	Process:       "process",
	Delete:        "delete",
}

func (e CgroupRateType) String() string {
	return totalLabelValues[e]
}

var (
	CgroupRateTotal = metrics.MustNewCounter(
		metrics.NewOpts(
			consts.MetricsNamespace, "", "cgroup_rate_total",
			"The total number of Tetragon cgroup rate counters. For internal use only.",
			nil, []metrics.ConstrainedLabel{{Name: "type", Values: slices.Collect(maps.Values(totalLabelValues))}}, nil,
		),
		nil,
	)
)

func RegisterMetrics(group metrics.Group) {
	group.MustRegister(CgroupRateTotal)
}

// Get a new handle on an ErrorTotal metric for an ErrorType
func GetCgroupRateTotal(cr CgroupRateType) prometheus.Counter {
	return CgroupRateTotal.WithLabelValues(cr.String())
}

// Increment an CgroupRateTotal for an CgroupRateType
func CgroupRateTotalInc(er CgroupRateType) {
	GetCgroupRateTotal(er).Inc()
}
