// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package overhead

import (
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/sensors/base"
	"github.com/prometheus/client_golang/prometheus"
)

func NewBPFCollector() prometheus.Collector {
	return metrics.NewCustomCollector(
		metrics.CustomMetrics{
			Time,
			Cnt,
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

	// Get policies/sensors/progs under sensor manager
	overheads, err := sm.ListOverheads()
	if err != nil {
		logger.GetLogger().WithError(err).Warn("error listing overheads to collect overheads metrics")
		return
	}

	for _, ovh := range overheads {
		ch <- Time.MustMetric(float64(ovh.RunTime), ovh.Namespace, ovh.Policy, ovh.Sensor, ovh.Attach)
		ch <- Cnt.MustMetric(float64(ovh.RunCnt), ovh.Namespace, ovh.Policy, ovh.Sensor, ovh.Attach)
	}

	// Get base sensor progs
	if overheads, ok := base.GetInitialSensor().Overhead(); ok {
		for _, ovh := range overheads {
			ch <- Time.MustMetric(float64(ovh.RunTime), "", "", ovh.Sensor, ovh.Attach)
			ch <- Cnt.MustMetric(float64(ovh.RunCnt), "", "", ovh.Sensor, ovh.Attach)
		}
	}
}

func collectForDocs(ch chan<- prometheus.Metric) {
	ch <- Time.MustMetric(0, "ns", "enforce", "generic_kprobe", "sys_open")
	ch <- Cnt.MustMetric(0, "ns", "enforce", "generic_kprobe", "sys_open")
}
