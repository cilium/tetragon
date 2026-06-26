// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package status

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/cmd/tetra/common"
)

func New() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Print health status",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := common.NewClientWithDefaultContextAndAddress()
			if err != nil {
				return fmt.Errorf("failed to create gRPC client: %w", err)
			}
			defer c.Close()

			response, err := c.Client.GetHealth(c.Ctx, &tetragon.GetHealthStatusRequest{})
			if err != nil {
				return fmt.Errorf("failed to get health status: %w", err)
			}
			healthStatus := response.GetHealthStatus()
			if len(healthStatus) == 0 {
				cmd.Println("Health Status: no status available")
				return nil
			}
			cmd.Printf("Health Status: %s\n", healthStatus[0].Details)
			return nil
		},
	}
}
