// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package observer

import (
	"testing"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors"
	tupf "github.com/cilium/tetragon/pkg/testutils/policyfilter"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
)

// GetTestSensorManager returns a new test sensor manager.
// Some tests require an observer running, some do not. To support both, the function checks if a
// sensor manager has already been setup in the observer, and uses it if so.
// Otherwise, it creates a new one. If it creates a new one it will use the test name to create a
// unqique directory for maps/etc, and will also register the necessary cleanup functions using
// t.Cleanup()
func GetTestSensorManager(t *testing.T) *tus.TestSensorManager {
	pfState, err := policyfilter.GetState()
	if err != nil {
		t.Fatalf("failed to initialize policy filter state: %s", err)
	}
	return getTestSensorManager(t, pfState)
}

func GetTestSensorManagerWithDummyPF(t *testing.T) *tus.TestSensorManager {
	return getTestSensorManager(t, &tupf.DummyPF{})
}

func getTestSensorManager(t *testing.T, pfState policyfilter.State) *tus.TestSensorManager {
	var mgr *sensors.Manager
	var err error

	if mgr = observer.GetSensorManager(); mgr != nil {
		return &tus.TestSensorManager{
			Manager: mgr,
		}
	}

	path := bpf.MapPrefixPath()
	mgr, err = sensors.StartSensorManagerWithPF(path, pfState)
	if err != nil {
		t.Fatalf("StartSensorManagerWithPF failed: %s", err)
	}

	return &tus.TestSensorManager{
		Manager: mgr,
	}
}
