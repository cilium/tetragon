// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metricsconfig

import (
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/kprobemetrics"
)

func registerHealthMetricsEx(group metrics.Group) {
	// kprobe metrics
	kprobemetrics.RegisterMetrics(group)
	group.ExtendInitForDocs(kprobemetrics.InitMetricsForDocs)
	// missed metrics
	group.MustRegister(kprobemetrics.NewBPFCollector())
}
