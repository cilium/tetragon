// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package observer

import (
	"fmt"
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
	ch <- mapmetrics.MapErrors.Desc()
}

func (c *bpfCollector) Collect(ch chan<- prometheus.Metric) {
	statsSuffix := "_stats"
	for _, m := range sensors.AllMaps {
		name := m.Name
		pin := filepath.Join(option.Config.MapDir, name)
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

		updateMapSize(ch, mapLinkStats, int(mapLink.MaxEntries()), name)
		updateMapErrors(ch, mapLinkStats, name)
	}
}

func updateMapSize(ch chan<- prometheus.Metric, mapLinkStats *ebpf.Map, maxEntries int, name string) {
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
		name, fmt.Sprint(maxEntries),
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
