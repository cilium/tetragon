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
	"github.com/cilium/tetragon/pkg/version"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func printClientersion() {
	fmt.Printf("cli version: %s\n", version.Version)
}

func printVersion(res *tetragon.GetVersionResponse, err error) {
	if err == nil {
		fmt.Printf("server version: %s\n", res.Version)
		printClientersion()
	} else {
		fmt.Printf("error getting server version: %s\n", err)
		printClientersion()
	}
}

func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print version",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			if viper.GetBool("client") {
				printClientersion()
				return
			}
			common.CliRunErr(
				func(ctx context.Context, cli tetragon.FineGuidanceSensorsClient) {
					res, err := cli.GetVersion(ctx, &tetragon.GetVersionRequest{})
					printVersion(res, err)
				},
				func(err error) {
					printVersion(nil, err)
				},
			)
		},
	}
	flags := cmd.Flags()
	flags.Bool("client", false, "Only print client version without attempting to connect to server")
	viper.BindPFlags(flags)
	return cmd
}
