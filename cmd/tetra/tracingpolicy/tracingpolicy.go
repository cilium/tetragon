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
)

func New() *cobra.Command {
	tpCmd := &cobra.Command{
		Use:   "tracingpolicy",
		Short: "Manage tracing policies",
	}

	tpAddCmd := &cobra.Command{
		Use:   "add <yaml_file>",
		Short: "add a new sensor based on a tracing policy",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			common.CliRun(func(ctx context.Context, cli tetragon.FineGuidanceSensorsClient) {
				addTracingPolicy(ctx, cli, args[0])
			})
		},
	}

	tpDelCmd := &cobra.Command{
		Use:   "delete <sensor_name>",
		Short: "delete a sensor",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			common.CliRun(func(ctx context.Context, cli tetragon.FineGuidanceSensorsClient) {
				deleteTracingPolicy(ctx, cli, args[0])
			})
		},
	}

	var tpListOutputFlag string
	tpListCmd := &cobra.Command{
		Use:   "list",
		Short: "list tracing policies",
		Args:  cobra.ExactArgs(0),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if tpListOutputFlag != "json" && tpListOutputFlag != "text" {
				return fmt.Errorf("invalid value for %q flag: %s", common.KeyOutput, tpListOutputFlag)
			}
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			common.CliRun(func(ctx context.Context, cli tetragon.FineGuidanceSensorsClient) {
				listTracingPolicies(ctx, cli, tpListOutputFlag)
			})
		},
	}
	tpListFlags := tpListCmd.Flags()
	tpListFlags.StringVarP(&tpListOutputFlag, common.KeyOutput, "o", "text", "Output format. text or json")

	var tpGenerateMatchBinary string
	tpGenerateCmd := &cobra.Command{
		Use:   "generate <all-syscalls|empty>",
		Short: "generate tracing policies",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			generateTracingPolicy(args[0], tpGenerateMatchBinary)
		},
	}

	tpGenerateFlags := tpGenerateCmd.Flags()
	tpGenerateFlags.StringVarP(&tpGenerateMatchBinary, "match-binary", "m", "", "Add binary to matchBinaries selector")

	tpCmd.AddCommand(tpAddCmd, tpDelCmd, tpListCmd, tpGenerateCmd)
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

func deleteTracingPolicy(ctx context.Context, client tetragon.FineGuidanceSensorsClient, name string) {
	_, err := client.DeleteTracingPolicy(ctx, &tetragon.DeleteTracingPolicyRequest{
		Name: name,
	})
	if err != nil {
		fmt.Printf("failed to delete tracing policy: %s\n", err)
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

func generateAllSyscalls(binary string) {
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

func generateTracingPolicy(cmd, binary string) {
	switch cmd {
	case "all-syscalls":
		generateAllSyscalls(binary)
	case "empty":
		generateEmpty()
	}
}
