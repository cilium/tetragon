// Copyright 2020 Authors of Hubble
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
