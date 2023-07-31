// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package mapmetrics

import (
	"fmt"

	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	MapSize = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "map_in_use_gauge",
		Help:        "The total number of in-use entries per map.",
		ConstLabels: nil,
	}, []string{"map", "total"})

	MapDrops = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "map_drops_total",
		Help:        "The total number of entries dropped per LRU map.",
		ConstLabels: nil,
	}, []string{"map"})

	MapErrors = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "map_errors_total",
		Help:        "The total number of entries dropped per LRU map.",
		ConstLabels: nil,
	}, []string{"map"})
)

func InitMetrics(registry *prometheus.Registry) {
	registry.MustRegister(MapSize)
	registry.MustRegister(MapDrops)
	registry.MustRegister(MapErrors)
}

// Get a new handle on a mapSize metric for a mapName and totalCapacity
func GetMapSize(mapName string, totalCapacity int) prometheus.Gauge {
	return MapSize.WithLabelValues(mapName, fmt.Sprint(totalCapacity))
}

func GetMapErrors(mapName string) prometheus.Gauge {
	return MapErrors.WithLabelValues(mapName)
}

// Increment a mapSize metric for a mapName and totalCapacity
func MapSizeInc(mapName string, totalCapacity int) {
	GetMapSize(mapName, totalCapacity).Inc()
}

// Set a mapSize metric to size for a mapName and totalCapacity
func MapSizeSet(mapName string, totalCapacity int, size float64) {
	GetMapSize(mapName, totalCapacity).Set(size)
}

func MapErrorSet(mapName string, errTotal float64) {
	GetMapErrors(mapName).Set(errTotal)
}

func MapDropInc(mapName string) {
	MapDrops.WithLabelValues(mapName).Inc()
}
