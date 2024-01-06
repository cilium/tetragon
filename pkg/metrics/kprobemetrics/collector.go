// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package kprobemetrics

import (
	"github.com/cilium/ebpf/link"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/unix"
)

// bpfCollector implements prometheus.Collector. It collects metrics directly from BPF maps.
type bpfCollector struct{}

func NewBPFCollector() prometheus.Collector {
	return &bpfCollector{}
}

func (c *bpfCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- MissedLink.Desc()
	ch <- MissedProg.Desc()
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
		pevent := info.PerfEvent()
		switch pevent.Type {
		case unix.BPF_PERF_EVENT_KPROBE, unix.BPF_PERF_EVENT_KRETPROBE:
			kprobe := pevent.Kprobe()
			missed, _ = kprobe.Missed()
		}
	case link.KprobeMultiType:
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

func (c *bpfCollector) Collect(ch chan<- prometheus.Metric) {
	allPrograms := sensors.AllPrograms()
	for _, prog := range allPrograms {
		collectLink(ch, prog)
		collectProg(ch, prog)
	}
}

// bpfZeroCollector implements prometheus.Collector. It collects "zero" metrics.
// It's intended to be used when BPF metrics are not collected, but we still want
// Prometheus metrics to be exposed.
type bpfZeroCollector struct {
	bpfCollector
}

func NewBPFZeroCollector() prometheus.Collector {
	return &bpfZeroCollector{
		bpfCollector: bpfCollector{},
	}
}

func (c *bpfZeroCollector) Describe(ch chan<- *prometheus.Desc) {
	c.bpfCollector.Describe(ch)
}

func (c *bpfZeroCollector) Collect(ch chan<- prometheus.Metric) {
	ch <- MissedLink.MustMetric(0, "policy", "attach")
	ch <- MissedProg.MustMetric(0, "policy", "attach")
}
