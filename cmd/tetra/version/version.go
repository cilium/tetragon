// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package version

import (
	"context"
	"fmt"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/cmd/tetra/common"
	"github.com/cilium/tetragon/pkg/logger"
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
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("CLI version: %s\n", version.Version)

			if server {
				common.CliRunErr(
					func(ctx context.Context, cli tetragon.FineGuidanceSensorsClient) {
						res, err := cli.GetVersion(ctx, &tetragon.GetVersionRequest{})
						if err != nil {
							logger.GetLogger().WithError(err).Error("error retrieving server version")
						}
						fmt.Printf("Server version: %s\n", res.Version)
					},
					func(err error) {
						logger.GetLogger().WithError(err).Error("error retrieving server version")
					},
				)
			}

			if build {
				info := version.ReadBuildInfo()
				info.Print()
			}
		},
	}
	flags := cmd.Flags()
	flags.BoolVarP(&server, "server", "s", false, "Connect and retrieve version from the server")
	flags.BoolVarP(&build, "build", "b", false, "Show CLI build information")
	return cmd
}
