// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package health

import (
	"github.com/cilium/tetragon/api/v1/tetragon"
)

var (
	grpcHealth = tetragon.HealthStatusResult_HEALTH_STATUS_RUNNING
)

func GetHealth() (*tetragon.GetHealthStatusResponse, error) {
	resp := &tetragon.GetHealthStatusResponse{}
	hs := &tetragon.HealthStatus{
		Event:   tetragon.HealthStatusType_HEALTH_STATUS_TYPE_STATUS,
		Status:  grpcHealth,
		Details: "running",
	}
	resp.HealthStatus = append(resp.HealthStatus, hs)
	return resp, nil
}
