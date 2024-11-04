// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package overhead

import (
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/observer"
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

	for _, ovh := range overheads {
		ch <- time.MustMetric(float64(ovh.RunTime), ovh.Namespace, ovh.Policy, ovh.Sensor, ovh.Attach, ovh.Label)
		ch <- runs.MustMetric(float64(ovh.RunCnt), ovh.Namespace, ovh.Policy, ovh.Sensor, ovh.Attach, ovh.Label)
	}
}

func collectForDocs(ch chan<- prometheus.Metric) {
	ch <- time.MustMetric(0, "ns", "enforce", "generic_kprobe", "sys_open", "kprobe/sys_open")
	ch <- runs.MustMetric(0, "ns", "enforce", "generic_kprobe", "sys_open", "kprobe/sys_open")
}
