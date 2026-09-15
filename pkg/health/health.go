// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package health

import (
	"sync/atomic"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

var ready atomic.Bool

// SetReady marks Tetragon as fully initialized. Before SetReady is called,
// GetHealth reports that the agent is still initializing.
func SetReady() {
	ready.Store(true)
}

// resetReady clears the ready flag. It is intended for tests that need to
// reset package-level state between runs.
func resetReady() {
	ready.Store(false)
}

func GetHealth() (*tetragon.GetHealthStatusResponse, error) {
	resp := &tetragon.GetHealthStatusResponse{}
	hs := &tetragon.HealthStatus{
		Event:   tetragon.HealthStatusType_HEALTH_STATUS_TYPE_STATUS,
		Status:  tetragon.HealthStatusResult_HEALTH_STATUS_UNDEF,
		Details: "initializing",
	}
	if ready.Load() {
		hs.Status = tetragon.HealthStatusResult_HEALTH_STATUS_RUNNING
		hs.Details = "running"
	}
	resp.HealthStatus = append(resp.HealthStatus, hs)
	return resp, nil
}
