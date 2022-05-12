// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package status

import (
	"context"
	"fmt"

	"github.com/cilium/tetragon/api/v1/fgs"
	"github.com/cilium/tetragon/cmd/tetra/common"
	"github.com/spf13/cobra"
)

func getStatus(ctx context.Context, client fgs.FineGuidanceSensorsClient) {
	response, err := client.GetHealth(ctx, &fgs.GetHealthStatusRequest{})
	if err != nil {
		fmt.Printf("status error: %s\n", err)
		return
	}
	fmt.Printf("Health Status: %s\n", response.GetHealthStatus()[0].Details)
}

func New() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Print health status",
		Run: func(cmd *cobra.Command, args []string) {
			common.CliRun(getStatus)
		},
	}
}
