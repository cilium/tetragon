// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package sensors

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSortSensorsGenericUprobeLast guards the resolvePathInContainer teardown
// invariant (see uprobe_ric_linux.go): "generic_uprobe" must sort after every
// sensor that can share its collection, so no sibling can fail to load after
// its PostLoad hooks ran. Policies are single-section, so the only possible
// sibling today is "__enforcer__", which always sorts first.
func TestSortSensorsGenericUprobeLast(t *testing.T) {
	sensors := []SensorIface{
		&Sensor{Name: "generic_uprobe"},
		&Sensor{Name: "__enforcer__"},
	}
	sortSensors(sensors)
	require.Equal(t, "__enforcer__", sensors[0].GetName())
	require.Equal(t, "generic_uprobe", sensors[len(sensors)-1].GetName())
}
