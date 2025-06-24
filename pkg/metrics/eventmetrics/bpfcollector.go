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
	var allCPUValue []processapi.KernelStats
	if err := mapHandle.Lookup(zero, &allCPUValue); err != nil {
		return
	}

	sum := processapi.KernelStats{}
	for _, val := range allCPUValue {
		for opcode, errors := range val.SentFailed {
			for er, count := range errors {
				sum.SentFailed[opcode][er] += count
			}
		}
	}

	for opcode, errors := range sum.SentFailed {
		for er, count := range errors {
			if count > 0 {
				ch <- MissedEvents.MustMetric(float64(count), strconv.Itoa(opcode), perfEventErrors[er])
			}
		}
	}
}

func collectForDocs(ch chan<- prometheus.Metric) {
	for _, opcode := range metrics.OpCodeLabel.Values {
		for _, er := range perfEventErrorLabel.Values {
			ch <- MissedEvents.MustMetric(0, opcode, er)
		}
	}
}
