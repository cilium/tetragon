// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package observer

import (
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics/mapmetrics"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

// bpfCollector implements prometheus.Collector. It collects metrics directly from BPF maps.
type bpfCollector struct{}

func NewBPFCollector() prometheus.Collector {
	return &bpfCollector{}
}

func (c *bpfCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- mapmetrics.MapSize.Desc()
	ch <- mapmetrics.MapCapacity.Desc()
	ch <- mapmetrics.MapErrors.Desc()
}

func (c *bpfCollector) Collect(ch chan<- prometheus.Metric) {
	statsSuffix := "_stats"
	// Depending on the sensors that are loaded and the dependencies between them,
	// sensors.AllMaps may have the same map name multiple times. This can cause in
	// errors like:
	// collected metric "XXX" {...} was collected before with the same name and label values
	// To avoid that we keep a map and we process each map only once.
	processedMaps := make(map[string]bool)
	for _, m := range sensors.AllMaps {
		name := m.Name
		if ok := processedMaps[name]; ok {
			// We have already got the stats of this map
			// so let's move to the next one.
			continue
		}
		processedMaps[name] = true
		pin := filepath.Join(option.Config.BpfDir, name)
		// Skip map names that end up with _stats.
		// This will result in _stats_stats suffixes that we don't care about
		if strings.HasSuffix(pin, statsSuffix) {
			continue
		}
		pinStats := pin + statsSuffix

		mapLinkStats, err := ebpf.LoadPinnedMap(pinStats, nil)
		if err != nil {
			// If we fail to open the map with _stats suffix
			// continue to the next map.
			continue
		}
		defer mapLinkStats.Close()
		mapLink, err := ebpf.LoadPinnedMap(pin, nil)
		if err != nil {
			// We have already opened the map with _stats suffix
			// so we don't expect that to fail.
			logger.GetLogger().WithFields(logrus.Fields{
				"MapName":      pin,
				"StatsMapName": pinStats,
			}).Warn("Failed to open the corresponding map for an existing stats map.")
			continue
		}
		defer mapLink.Close()

		updateMapSize(ch, mapLinkStats, name)
		ch <- mapmetrics.MapCapacity.MustMetric(
			float64(mapLink.MaxEntries()),
			name,
		)
		updateMapErrors(ch, mapLinkStats, name)
	}
}

func updateMapSize(ch chan<- prometheus.Metric, mapLinkStats *ebpf.Map, name string) {
	var values []int64
	if err := mapLinkStats.Lookup(int32(0), &values); err != nil {
		return
	}

	sum := int64(0)
	for _, n := range values {
		sum += n
	}
	ch <- mapmetrics.MapSize.MustMetric(
		float64(sum),
		name,
	)
}

func updateMapErrors(ch chan<- prometheus.Metric, mapLinkStats *ebpf.Map, name string) {
	var values []int64
	if err := mapLinkStats.Lookup(int32(1), &values); err != nil {
		return
	}

	sum := int64(0)
	for _, n := range values {
		sum += n
	}
	ch <- mapmetrics.MapErrors.MustMetric(
		float64(sum),
		name,
	)
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
	// This list should contain all monitored maps.
	// These are not maps from which metrics are read in the "real" collector -
	// the metrics are stored in separate maps suffixed with "_stats".
	monitoredMaps := []string{
		"execve_map",
		"tg_execve_joined_info_map",
	}
	for _, m := range monitoredMaps {
		ch <- mapmetrics.MapSize.MustMetric(
			0,
			m,
		)
		ch <- mapmetrics.MapCapacity.MustMetric(
			0,
			m,
		)
		ch <- mapmetrics.MapErrors.MustMetric(
			0,
			m,
		)
	}
}
