// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package overhead

import (
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/prometheus/client_golang/prometheus"
)

func NewBPFCollector() prometheus.Collector {
	return metrics.NewCustomCollector(
		metrics.CustomMetrics{
			time,
			runs,
		},
		collect,
		collectForDocs,
	)
}

func collect(ch chan<- prometheus.Metric) {
	sm := observer.GetSensorManager()
	if sm == nil {
		logger.GetLogger().Debug("failed retrieving the sensor manager: manager is nil")
		return
	}

	overheads, err := sm.ListOverheads()
	if err != nil {
		logger.GetLogger().WithError(err).Warn("error listing overheads to collect overheads metrics")
		return
	}

	// Aggregate metrics before reporting, to avoid duplicates that would cause
	// the entire metrics collection job to fail.
	times := map[sensors.Prog]uint64{}
	counts := map[sensors.Prog]uint64{}
	for _, ovh := range overheads {
		times[ovh.Prog] += ovh.RunTime
		counts[ovh.Prog] += ovh.RunCnt
	}
	for prog, m := range times {
		ch <- time.MustMetric(float64(m), prog.Namespace, prog.Policy, prog.Sensor, prog.Attach, prog.Label)
	}
	for prog, m := range counts {
		ch <- runs.MustMetric(float64(m), prog.Namespace, prog.Policy, prog.Sensor, prog.Attach, prog.Label)
	}
}

func collectForDocs(ch chan<- prometheus.Metric) {
	ch <- time.MustMetric(0, "ns", "enforce", "generic_kprobe", "sys_open", "kprobe/sys_open")
	ch <- runs.MustMetric(0, "ns", "enforce", "generic_kprobe", "sys_open", "kprobe/sys_open")
}
