// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

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
