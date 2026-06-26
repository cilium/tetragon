// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package version

import (
	"fmt"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/cmd/tetra/common"
	"github.com/cilium/tetragon/pkg/version"

	"github.com/spf13/cobra"
)

const examples = `  # Retrieve version from server
  tetra version --server

  # Get build info for the CLI
  tetra version --build`

var (
	server bool
	build  bool
)

func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "version",
		Short:   "Print version from CLI and server",
		Example: examples,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.Printf("CLI version: %s\n", version.Version)

			if server {
				c, err := common.NewClientWithDefaultContextAndAddress()
				if err != nil {
					return fmt.Errorf("failed to create gRPC client: %w", err)
				}
				defer c.Close()

				res, err := c.Client.GetVersion(c.Ctx, &tetragon.GetVersionRequest{})
				if err != nil {
					return fmt.Errorf("failed to retrieve server version: %w", err)
				}
				cmd.Printf("Server version: %s\n", res.Version)
			}

			if build {
				info := version.ReadBuildInfo()
				info.Print()
			}
			return nil
		},
	}
	flags := cmd.Flags()
	flags.BoolVarP(&server, "server", "s", false, "Connect and retrieve version from the server")
	flags.BoolVarP(&build, "build", "b", false, "Show CLI build information")
	return cmd
}
