// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package info

import (
	"encoding/json"
	"fmt"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/cmd/tetra/common"
	"github.com/cilium/tetragon/pkg/tetragoninfo"

	"github.com/spf13/cobra"
)

func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "info",
		Short: "Retrieve information from the server",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cli, err := common.NewClientWithDefaultContextAndAddress()
			if err != nil {
				return fmt.Errorf("failed to create client: %w", err)
			}

			res, err := cli.Client.GetInfo(cli.Ctx, &tetragon.GetInfoRequest{})
			if err != nil {
				return fmt.Errorf("failed to retrieve info: %w", err)
			}

			info := tetragoninfo.Decode(res)
			b, err := json.Marshal(info)
			if err != nil {
				return fmt.Errorf("failed to marshal info: %w", err)
			}
			cmd.Println(string(b))
			return nil
		},
	}
	return cmd
}
