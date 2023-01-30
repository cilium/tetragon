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

package tracingpolicy

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/cmd/tetra/common"
	"github.com/spf13/cobra"
)

func New() *cobra.Command {
	tpCmd := &cobra.Command{
		Use:   "tracingpolicy",
		Short: "Manage tracing policies",
	}

	tpAddCmd := &cobra.Command{
		Use:   "add <yaml_file>",
		Short: "Add a new sensor based on a tracing policy",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			common.CliRun(func(ctx context.Context, cli tetragon.FineGuidanceSensorsClient) {
				addTracingPolicy(ctx, cli, args[0])
			})
		},
	}
	tpCmd.AddCommand(tpAddCmd)

	tpListCmd := &cobra.Command{
		Use:   "list",
		Short: "list tracing policies",
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			common.CliRun(func(ctx context.Context, cli tetragon.FineGuidanceSensorsClient) {
				listTragingPolicies(ctx, cli)
			})
		},
	}

	tpCmd.AddCommand(tpAddCmd, tpListCmd)

	return tpCmd
}

func addTracingPolicy(ctx context.Context, client tetragon.FineGuidanceSensorsClient, yamlFname string) {
	yamlb, err := os.ReadFile(yamlFname)
	if err != nil {
		fmt.Printf("failed to read yaml file %s: %s\n", yamlFname, err)
		return
	}

	_, err = client.AddTracingPolicy(ctx, &tetragon.AddTracingPolicyRequest{
		Yaml: string(yamlb),
	})
	if err != nil {
		fmt.Printf("failed to add tracing policy: %s\n", err)
	}
}

func listTragingPolicies(ctx context.Context, client tetragon.FineGuidanceSensorsClient) {

	res, err := client.ListTracingPolicies(ctx, &tetragon.ListTracingPoliciesRequest{})
	if err != nil || res == nil {
		fmt.Printf("failed to list tracing policies: %s\n", err)
		return
	}

	for _, pol := range res.Policies {
		namespace := pol.Namespace
		if namespace == "" {
			namespace = "(global)"
		}

		sensors := strings.Join(pol.Sensors, ",")
		fmt.Printf("%d %s (%s) %s %s\n", pol.Id, pol.Name, pol.Info, namespace, sensors)
	}
}
