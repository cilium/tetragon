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
	"github.com/cilium/tetragon/pkg/btf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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

	tpListCmd := &cobra.Command{
		Use:   "list",
		Short: "list tracing policies",
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			output := viper.GetString(common.KeyOutput)
			switch output {
			case "json", "text":
				// valid
			default:
				logger.GetLogger().WithField(common.KeyOutput, output).Fatal("invalid output flag")
			}
			common.CliRun(func(ctx context.Context, cli tetragon.FineGuidanceSensorsClient) {
				listTracingPolicies(ctx, cli, output)
			})
		},
	}
	tpListFlags := tpListCmd.Flags()
	tpListFlags.StringP(common.KeyOutput, "o", "text", "Output format. json or text")
	viper.BindPFlags(tpListFlags)

	tpGenerateCmd := &cobra.Command{
		Use:   "generate",
		Short: "generate tracing policies",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			generateTracingPolicy(args[0])
		},
	}

	flags := tpGenerateCmd.Flags()
	flags.String("match-binary", "", "Add binary to matchBinaries selector")
	viper.BindPFlags(flags)

	tpCmd.AddCommand(tpAddCmd, tpListCmd, tpGenerateCmd)
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

func listTracingPoliciesText(res *tetragon.ListTracingPoliciesResponse) {
	for _, pol := range res.Policies {
		namespace := pol.Namespace
		if namespace == "" {
			namespace = "(global)"
		}

		sensors := strings.Join(pol.Sensors, ",")
		fmt.Printf("%d %s (%s) %s %s\n", pol.Id, pol.Name, pol.Info, namespace, sensors)
	}
}

func listTracingPolicies(
	ctx context.Context,
	client tetragon.FineGuidanceSensorsClient,
	output string) {

	res, err := client.ListTracingPolicies(ctx, &tetragon.ListTracingPoliciesRequest{})
	if err != nil || res == nil {
		logger.GetLogger().WithError(err).Fatal("failed to list tracing policies")
	}

	if output == "json" {
		b, err := res.MarshalJSON()
		if err != nil {
			logger.GetLogger().WithError(err).Fatal("failed to generate json")
		}
		fmt.Println(string(b))
	} else {
		listTracingPoliciesText(res)
	}
}

func generateAllSyscalls() {
	binary := viper.GetString("match-binary")
	crd, err := btf.GetSyscallsYaml(binary)
	if err != nil {
		fmt.Print(err)
		return
	}
	fmt.Printf("%s\n", crd)
}

func generateEmpty() {
	crd := `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "empty" `

	fmt.Printf("%s\n", crd)
}

func generateTracingPolicy(cmd string) {
	switch cmd {
	case "all-syscalls":
		generateAllSyscalls()
	case "empty":
		generateEmpty()
	}
}
