// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package observer

import (
	"errors"
	"sync"

	"github.com/cilium/tetragon/pkg/sensors"
)

var (
	// SensorManager handles dynamic sensors loading / unloading, and is a global variable for
	// now
	sensorManager   *sensors.Manager
	sensorManagerMu sync.Mutex
)

// ResetSensorManager resets the global sensorManager variable to nil. Intended only for testing.
func ResetSensorManager() {
	sensorManager = nil
}

func SetSensorManager(sm *sensors.Manager) error {
	sensorManagerMu.Lock()
	defer sensorManagerMu.Unlock()

	if sensorManager != nil {
		return errors.New("observer sensorManager already set")
	}
	sensorManager = sm
	return nil
}

func GetSensorManager() *sensors.Manager {
	sensorManagerMu.Lock()
	defer sensorManagerMu.Unlock()
	return sensorManager
}
