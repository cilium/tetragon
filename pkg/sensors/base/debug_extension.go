// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package base

import (
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

var (
	// Debug maps - only created when next-gen debug is enabled
	DebugHeapMap   *program.Map
	DebugEventsMap *program.Map
)

func init() {
	// Register the debug extension to be applied when the base sensor is initialized
	RegisterExtensionAtInit("debug-maps", applyDebugExtension)
}

// GetDebugHeapMap returns the debug heap map if it exists
func GetDebugHeapMap() *program.Map {
	return DebugHeapMap
}

// GetDebugEventsMap returns the debug events map if it exists
func GetDebugEventsMap() *program.Map {
	return DebugEventsMap
}

// applyDebugExtension adds debug-related maps to the base sensor when perf debug is enabled
func applyDebugExtension(sensor *sensors.Sensor) (*sensors.Sensor, error) {
	if !option.Config.EnablePerfDebug {
		return sensor, nil
	}

	logger.GetLogger().Info("Applying debug extension to base sensor")

	// Create debug maps and associate them with the platform-specific program
	debugHeapMap := program.MapBuilder("debug_heap", getPlatformDebugProgram())
	debugEventsMap := program.MapBuilder("debug_events", getPlatformDebugProgram())

	// Store references to the debug maps for potential external access
	DebugHeapMap = debugHeapMap
	DebugEventsMap = debugEventsMap

	// Add debug maps to the sensor
	sensor.Maps = append(sensor.Maps, debugHeapMap, debugEventsMap)

	return sensor, nil
}
