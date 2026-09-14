// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package health

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

func TestGetHealthInitializing(t *testing.T) {
	resetReady()
	t.Cleanup(resetReady)

	resp, err := GetHealth()
	require.NoError(t, err)
	assert.Len(t, resp.GetHealthStatus(), 1)
	assert.Equal(t, tetragon.HealthStatusResult_HEALTH_STATUS_UNDEF, resp.GetHealthStatus()[0].Status)
	assert.Equal(t, "initializing", resp.GetHealthStatus()[0].Details)
}

func TestGetHealthRunning(t *testing.T) {
	resetReady()
	t.Cleanup(resetReady)
	SetReady()

	resp, err := GetHealth()
	require.NoError(t, err)
	assert.Len(t, resp.GetHealthStatus(), 1)
	assert.Equal(t, tetragon.HealthStatusResult_HEALTH_STATUS_RUNNING, resp.GetHealthStatus()[0].Status)
	assert.Equal(t, "running", resp.GetHealthStatus()[0].Details)
}
