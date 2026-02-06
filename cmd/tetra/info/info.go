// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package info

import (
	"context"
	"encoding/json"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/cmd/tetra/common"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/tetragoninfo"

	"github.com/spf13/cobra"
)

func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "info",
		Short: "Retrieve information from the server",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			common.CliRunErr(
				func(ctx context.Context, cli tetragon.FineGuidanceSensorsClient) {
					res, err := cli.GetInfo(ctx, &tetragon.GetInfoRequest{})
					if err != nil {
						logger.GetLogger().Error("error retrieving server info", logfields.Error, err)
						return
					}

					info := tetragoninfo.Decode(res)
					b, err := json.Marshal(info)
					if err != nil {
						logger.GetLogger().Error("failed to generate json", logfields.Error, err)
						return
					}
					cmd.Println(string(b))
				},
				func(err error) {
					logger.GetLogger().Error("error retrieving server info", logfields.Error, err)
				},
			)
		},
	}
	return cmd
}
