// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package health

import (
	"github.com/cilium/tetragon/api/v1/fgs"
)

var (
	grpcHealth = fgs.HealthStatusResult_HEALTH_STATUS_RUNNING
)

func GetHealth() (*fgs.GetHealthStatusResponse, error) {
	resp := &fgs.GetHealthStatusResponse{}
	hs := &fgs.HealthStatus{
		Event:   fgs.HealthStatusType_HEALTH_STATUS_TYPE_STATUS,
		Status:  grpcHealth,
		Details: "running",
	}
	resp.HealthStatus = append(resp.HealthStatus, hs)
	return resp, nil
}
