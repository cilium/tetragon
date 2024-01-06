// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package kprobemetrics

import (
	"github.com/cilium/ebpf/link"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/unix"
)

func NewBPFCollector() prometheus.Collector {
	return metrics.NewCustomCollector(
		metrics.CustomMetrics{
			MissedLink,
			MissedProg,
		},
		collect,
		collectForDocs,
	)
}

func collectLink(ch chan<- prometheus.Metric, load *program.Program) {
	if load.Link == nil {
		return
	}

	info, err := load.Link.Info()
	if err != nil {
		return
	}

	missed := uint64(0)

	switch info.Type {
	case link.PerfEventType:
		if !bpf.HasMissedStatsPerfEvent() {
			return
		}
		pevent := info.PerfEvent()
		switch pevent.Type {
		case unix.BPF_PERF_EVENT_KPROBE, unix.BPF_PERF_EVENT_KRETPROBE:
			kprobe := pevent.Kprobe()
			missed, _ = kprobe.Missed()
		}
	case link.KprobeMultiType:
		if !bpf.HasMissedStatsKprobeMulti() {
			return
		}
		kmulti := info.KprobeMulti()
		missed, _ = kmulti.Missed()
	default:
	}

	ch <- MissedLink.MustMetric(float64(missed), load.Policy, load.Attach)
}

func collectProg(ch chan<- prometheus.Metric, load *program.Program) {
	info, err := load.Prog.Info()
	if err != nil {
		return
	}

	missed, _ := info.RecursionMisses()
	ch <- MissedProg.MustMetric(float64(missed), load.Policy, load.Attach)
}

func collect(ch chan<- prometheus.Metric) {
	allPrograms := sensors.AllPrograms()
	for _, prog := range allPrograms {
		collectLink(ch, prog)
		collectProg(ch, prog)
	}
}

func collectForDocs(ch chan<- prometheus.Metric) {
	ch <- MissedLink.MustMetric(0, "monitor_panic", "sys_panic")
	ch <- MissedProg.MustMetric(0, "monitor_panic", "sys_panic")
}
