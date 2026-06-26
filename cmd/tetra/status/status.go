// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package status

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/cmd/tetra/common"
)

func getStatus(ctx context.Context, client tetragon.FineGuidanceSensorsClient) {
	response, err := client.GetHealth(ctx, &tetragon.GetHealthStatusRequest{})
	if err != nil {
		fmt.Printf("status error: %s\n", err)
		return
	}
	healthStatus := response.GetHealthStatus()
	if len(healthStatus) == 0 {
		fmt.Println("Health Status: no status available")
		return
	}
	fmt.Printf("Health Status: %s\n", healthStatus[0].Details)
}

func New() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Print health status",
		Run: func(_ *cobra.Command, _ []string) {
			common.CliRun(getStatus)
		},
	}
}
