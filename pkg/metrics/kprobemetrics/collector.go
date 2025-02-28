// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux

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

func collectLink(load *program.Program) (uint64, bool) {
	if load.Link == nil {
		return 0, false
	}

	info, err := load.Link.Info()
	if err != nil {
		return 0, false
	}

	switch info.Type {
	case link.PerfEventType:
		if !bpf.HasMissedStatsPerfEvent() {
			return 0, false
		}
		pevent := info.PerfEvent()
		switch pevent.Type {
		case unix.BPF_PERF_EVENT_KPROBE, unix.BPF_PERF_EVENT_KRETPROBE:
			kprobe := pevent.Kprobe()
			return kprobe.Missed()
		}
	case link.KprobeMultiType:
		if !bpf.HasMissedStatsKprobeMulti() {
			return 0, false
		}
		kmulti := info.KprobeMulti()
		return kmulti.Missed()
	}

	return 0, false
}

func collectProg(load *program.Program) (uint64, bool) {
	info, err := load.Prog.Info()
	if err != nil {
		return 0, false
	}

	return info.RecursionMisses()
}

type missedKey struct {
	policy string
	attach string
}

func collect(ch chan<- prometheus.Metric) {
	allPrograms := sensors.AllPrograms()

	mapProg := make(map[missedKey]uint64)
	mapLink := make(map[missedKey]uint64)

	// Group all the metrics together so we avoid of duplicate
	// metric values due to missing policy name.

	for _, load := range allPrograms {
		valLink, okLink := collectLink(load)
		valProg, okProg := collectProg(load)

		// Store metrics only when we retrieved them successfully.
		if !okLink && !okProg {
			continue
		}

		key := missedKey{load.Policy, load.Attach}

		if okLink {
			mapLink[key] = mapLink[key] + valLink
		}
		if okProg {
			mapProg[key] = mapProg[key] + valProg
		}
	}

	for key, val := range mapProg {
		ch <- MissedProg.MustMetric(float64(val), key.policy, key.attach)
	}

	for key, val := range mapLink {
		ch <- MissedLink.MustMetric(float64(val), key.policy, key.attach)
	}
}

func collectForDocs(ch chan<- prometheus.Metric) {
	ch <- MissedLink.MustMetric(0, "monitor_panic", "sys_panic")
	ch <- MissedProg.MustMetric(0, "monitor_panic", "sys_panic")
}
