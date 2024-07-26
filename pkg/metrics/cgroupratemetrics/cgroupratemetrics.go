// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package cgroupratemetrics

import (
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
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
	CgroupRateTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "cgroup_rate_total",
		Help:        "The total number of Tetragon cgroup rate counters. For internal use only.",
		ConstLabels: nil,
	}, []string{"type"})
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
