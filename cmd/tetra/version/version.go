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

	"github.com/cilium/tetragon/api/v1/fgs"
	"github.com/cilium/tetragon/cmd/tetra/common"
	"github.com/cilium/tetragon/pkg/version"

	"github.com/spf13/cobra"
)

func printVersion(res *fgs.GetVersionResponse, err error) {
	if err == nil {
		fmt.Printf("server version: %s cli version: %s\n", res.Version, version.Version)
	} else {
		fmt.Printf("error getting server version: %s\n", err)
		fmt.Printf("cli version: %s\n", version.Version)
	}
}

func New() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			common.CliRunErr(
				func(ctx context.Context, cli fgs.FineGuidanceSensorsClient) {
					res, err := cli.GetVersion(ctx, &fgs.GetVersionRequest{})
					printVersion(res, err)
				},
				func(err error) {
					printVersion(nil, err)
				},
			)
		},
	}
}
