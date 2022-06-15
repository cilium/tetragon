// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package mapmetrics

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/logger"
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

	SensorMapsLoaded = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:        consts.MetricNamePrefix + "sensor_maps_loaded",
		Help:        "Sensor maps currently loaded into the kernel. A number higher than 1 means that a map was loaded more than once without being pinned.",
		ConstLabels: nil,
	}, []string{"map_name", "map_type"})

	SensorMapsRefcounts = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:        consts.MetricNamePrefix + "sensor_maps_refcounts",
		Help:        "Number of sensors that hold a reference to a pinned map.",
		ConstLabels: nil,
	}, []string{"map_name", "map_type"})
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

// Maps the are registered for loader metrics. These will be polled at regular intervals.
var registeredMaps = make(map[registeredMapsKey]struct{})

type registeredMapsKey struct {
	name  string
	type_ ebpf.MapType
}

// Increment the pin count metrics for this map.
func IncPinCount(m *ebpf.Map) {
	info, err := m.Info()
	if err != nil {
		logger.GetLogger().WithError(err).Debug("failed to increment pin metrics, no map info")
		return
	}

	SensorMapsRefcounts.WithLabelValues(info.Name, info.Type.String()).Inc()
}

// Decrement the pin count metrics for this map.
func DecPinCount(m *ebpf.Map) {
	info, err := m.Info()
	if err != nil {
		logger.GetLogger().WithError(err).Debug("failed to decrement pin metrics, no map info")
		return
	}

	SensorMapsRefcounts.WithLabelValues(info.Name, info.Type.String()).Dec()
}

// Register a map to be tracked by loader metrics.
func RegisterMap(m *ebpf.Map) {
	info, err := m.Info()
	if err != nil {
		logger.GetLogger().WithError(err).Debug("failed to register map for metrics, no map info")
		return
	}

	key := registeredMapsKey{
		name:  info.Name,
		type_: info.Type,
	}

	registeredMaps[key] = struct{}{}
}

func UpdateMapLoadedMetrics() {
	loadedMapsCount := make(map[registeredMapsKey]int)

	var id ebpf.MapID
	for {
		var err error
		id, err = ebpf.MapGetNextID(id)
		if err != nil {
			break
		}

		m, err := ebpf.NewMapFromID(id)
		if err != nil {
			logger.GetLogger().WithError(err).WithField("ID", id).Debug("UpdateMapLoadedMetrics: failed to create map from ID")
			continue
		}

		info, err := m.Info()
		if err != nil {
			logger.GetLogger().WithError(err).WithField("ID", id).Debug("UpdateMapLoadedMetrics: failed to get map info")
			continue
		}

		key := registeredMapsKey{
			name:  info.Name,
			type_: info.Type,
		}

		_, ok := registeredMaps[key]
		if !ok {
			continue
		}

		loadedMapsCount[key]++
	}

	for key, count := range loadedMapsCount {
		SensorMapsLoaded.WithLabelValues(key.name, key.type_.String()).Set(float64(count))
	}
}
