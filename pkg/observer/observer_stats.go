// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package observer

import (
	"fmt"
	"path/filepath"
	"runtime"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics/mapmetrics"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors"
)

type statKey struct {
	Key int32
}

type statValue struct {
	Value []int64 // kernel rounds up to 64bits so pretend its a 64bit here
}

func (k *statKey) String() string            { return fmt.Sprintf("key=%d", k.Key) }
func (k *statKey) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }
func (k *statKey) NewValue() bpf.MapValue {
	return &statValue{
		Value: make([]int64, runtime.NumCPU()),
	}
}
func (k *statKey) DeepCopyMapKey() bpf.MapKey { return &statKey{k.Key} }

func (s *statValue) String() string {
	return fmt.Sprintf("%v", s.Value)
}
func (s *statValue) GetValuePtr() unsafe.Pointer {
	return unsafe.Pointer(&s.Value[0])
}
func (s *statValue) DeepCopyMapValue() bpf.MapValue {
	v := &statValue{
		Value: make([]int64, runtime.NumCPU()),
	}
	copy(v.Value, s.Value)
	return v
}

// UpdateSensorMapsLoaded updates the count of loaded sensor maps
func UpdateSensorMapsLoaded() {
	registeredMapNames := make(map[string]struct{})
	mapCounts := make(map[struct {
		string
		ebpf.MapType
	}]int)

	for _, m := range sensors.AllMaps {
		if m == nil {
			continue
		}

		// Map names in the kernel are truncated to 16 chars
		var truncatedName = m.Name
		if len(truncatedName) > 16 {
			truncatedName = truncatedName[:16]
		}

		logger.GetLogger().WithField("name", m.Name).Debug("UpdateSensorMapsLoaded: Found sensor map")

		// Register the map name
		registeredMapNames[truncatedName] = struct{}{}

		// Update the refcount metrics
		var typeStr string
		type_, err := m.Type()
		if err == nil {
			typeStr = type_.String()
		} else {
			logger.GetLogger().WithField("name", m.Name).WithError(err).Debug("UpdateSensorMapsLoaded: Failed to get map type")
			continue
		}
		mapmetrics.SensorMapsRefcounts.WithLabelValues(m.Name, typeStr).Set(float64(m.PinState.Count()))
	}

	var id ebpf.MapID
	for {
		var err error
		id, err = ebpf.MapGetNextID(id)
		if err != nil {
			break
		}

		m, err := ebpf.NewMapFromID(id)
		if err != nil {
			logger.GetLogger().WithError(err).WithField("ID", id).Debug("UpdateSensorMapsLoaded: Failed to create map from ID")
			continue
		}

		i, err := m.Info()
		if err != nil {
			logger.GetLogger().WithError(err).WithField("ID", id).Debug("UpdateSensorMapsLoaded: Failed to get map info")
			continue
		}

		if _, ok := registeredMapNames[i.Name]; !ok {
			logger.GetLogger().WithField("ID", id).WithField("name", i.Name).Debug("UpdateSensorMapsLoaded: Skipping non-sensor map")
			continue
		}

		logger.GetLogger().WithField("ID", id).WithField("name", i.Name).Debug("UpdateSensorMapsLoaded: Incrementing metrics count for map")
		mapCounts[struct {
			string
			ebpf.MapType
		}{i.Name, i.Type}]++
	}

	for info, count := range mapCounts {
		mapmetrics.SensorMapsLoaded.WithLabelValues(info.string, info.MapType.String()).Set(float64(count))
	}
}

func (k *Observer) startUpdateMapMetrics() {
	update := func() {
		for _, m := range sensors.AllMaps {
			pin := filepath.Join(option.Config.MapDir, m.Name)
			pinStats := pin + "_stats"

			mapLinkStats, err := bpf.OpenMap(pinStats)
			if err != nil {
				continue
			}
			mapLink, err := bpf.OpenMap(pin)
			if err != nil {
				continue
			}

			zeroKey := &statKey{}
			value, err := mapLinkStats.Lookup(zeroKey)
			if err != nil {
				continue
			}

			v, ok := value.DeepCopyMapValue().(*statValue)
			if !ok {
				continue
			}
			sum := int64(0)
			for cpu := int(0); cpu < runtime.NumCPU(); cpu++ {
				sum += v.Value[cpu]
			}
			mapmetrics.MapSizeSet(m.Name, int(mapLink.MapInfo.MaxEntries), float64(sum))
			mapLink.Close()
			mapLinkStats.Close()
		}
	}

	ticker := time.NewTicker(30 * time.Second)
	go func() {
		for {
			select {
			case <-ticker.C:
				update()
			}
		}
	}()

	// Map loaded sensor map metrics
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		for {
			UpdateSensorMapsLoaded()
			select {
			case <-ticker.C: // Wait for timer
			}
		}
	}()
}
