// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package eventmetrics

import (
	"path/filepath"
	"strconv"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/prometheus/client_golang/prometheus"
)

func NewBPFCollector() metrics.CollectorWithInit {
	return metrics.NewCustomCollector(
		metrics.CustomMetrics{
			MissedEvents,
		},
		collect,
		collectForDocs,
	)
}

func collect(ch chan<- prometheus.Metric) {
	mapHandle, err := ebpf.LoadPinnedMap(filepath.Join(option.Config.BpfDir, "tg_stats_map"), nil)
	if err != nil {
		return
	}
	defer mapHandle.Close()

	var zero uint32
	var allCpuValue []processapi.KernelStats
	if err := mapHandle.Lookup(zero, &allCpuValue); err != nil {
		return
	}

	sum := processapi.KernelStats{}
	for _, val := range allCpuValue {
		for i, data := range val.SentFailed {
			sum.SentFailed[i] += data
		}
	}

	for i, data := range sum.SentFailed {
		if data > 0 {
			ch <- MissedEvents.MustMetric(float64(data), strconv.Itoa(i))
		}
	}
}

func collectForDocs(ch chan<- prometheus.Metric) {
	for _, opcode := range metrics.OpCodeLabel.Values {
		ch <- MissedEvents.MustMetric(0, opcode)
	}
}
