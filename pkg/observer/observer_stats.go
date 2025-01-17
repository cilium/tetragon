// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package observer

import (
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/mapmetrics"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

func NewBPFCollector() metrics.CollectorWithInit {
	return metrics.NewCustomCollector(
		metrics.CustomMetrics{
			mapmetrics.MapSize,
			mapmetrics.MapCapacity,
			mapmetrics.MapErrorsUpdate,
			mapmetrics.MapErrorsDelete,
		},
		collect,
		collectForDocs,
	)
}

func collect(ch chan<- prometheus.Metric) {
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

		ch <- mapmetrics.MapCapacity.MustMetric(
			float64(mapLink.MaxEntries()),
			name,
		)
		update(mapLinkStats, 0, func(sum float64) {
			ch <- mapmetrics.MapSize.MustMetric(sum, name)
		})
		update(mapLinkStats, 1, func(sum float64) {
			ch <- mapmetrics.MapErrorsUpdate.MustMetric(sum, name)
		})
		update(mapLinkStats, 2, func(sum float64) {
			ch <- mapmetrics.MapErrorsDelete.MustMetric(sum, name)
		})
	}
}

func update(mapLinkStats *ebpf.Map, key int32, update func(sum float64)) {
	var values []int64

	if err := mapLinkStats.Lookup(key, &values); err != nil {
		return
	}

	sum := int64(0)
	for _, n := range values {
		sum += n
	}
	update(float64(sum))
}

func collectForDocs(ch chan<- prometheus.Metric) {
	for _, m := range mapmetrics.MapLabel.Values {
		ch <- mapmetrics.MapSize.MustMetric(0, m)
		ch <- mapmetrics.MapCapacity.MustMetric(0, m)
		ch <- mapmetrics.MapErrorsUpdate.MustMetric(0, m)
		ch <- mapmetrics.MapErrorsDelete.MustMetric(0, m)
	}
}
