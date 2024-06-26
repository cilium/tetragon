// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package kprobemetrics

import (
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	MissedLink = metrics.NewBPFCounter(prometheus.NewDesc(
		prometheus.BuildFQName(consts.MetricsNamespace, "", "missed_link_probes_total"),
		"The total number of Tetragon probe missed by link.",
		[]string{"policy", "attach"}, nil,
	))
	MissedProg = metrics.NewBPFCounter(prometheus.NewDesc(
		prometheus.BuildFQName(consts.MetricsNamespace, "", "missed_prog_probes_total"),
		"The total number of Tetragon probe missed by program.",
		[]string{"policy", "attach"}, nil,
	))
)
