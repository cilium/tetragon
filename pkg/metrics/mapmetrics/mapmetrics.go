// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package mapmetrics

import (
	"fmt"

	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	MapSize = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:        consts.MetricNamePrefix + "map_in_use_gauge",
		Help:        "The total number of in-use entries per map.",
		ConstLabels: nil,
	}, []string{"map", "total"})

	MapDrops = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:        consts.MetricNamePrefix + "map_drops",
		Help:        "The total number of entries dropped per LRU map.",
		ConstLabels: nil,
	}, []string{"map"})
)

// Get a new handle on a mapSize metric for a mapName and totalCapacity
func GetMapSize(mapName string, totalCapacity int) prometheus.Gauge {
	return MapSize.WithLabelValues(mapName, fmt.Sprint(totalCapacity))
}

// Increment a mapSize metric for a mapName and totalCapacity
func MapSizeInc(mapName string, totalCapacity int) {
	GetMapSize(mapName, totalCapacity).Inc()
}

// Set a mapSize metric to size for a mapName and totalCapacity
func MapSizeSet(mapName string, totalCapacity int, size float64) {
	GetMapSize(mapName, totalCapacity).Set(size)
}

func MapDropInc(mapName string) {
	MapDrops.WithLabelValues(mapName).Inc()
}
