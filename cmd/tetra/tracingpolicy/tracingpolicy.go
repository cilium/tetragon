// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package tracingpolicy

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/cmd/tetra/common"
	"github.com/cilium/tetragon/cmd/tetra/tracingpolicy/generate"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/spf13/cobra"
)

func New() *cobra.Command {
	tpCmd := &cobra.Command{
		Use:     "tracingpolicy",
		Aliases: []string{"tp"},
		Short:   "Manage tracing policies",
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
		Use:   "delete <name>",
		Short: "delete a tracing policy",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			common.CliRun(func(ctx context.Context, cli tetragon.FineGuidanceSensorsClient) {
				deleteTracingPolicy(ctx, cli, args[0])
			})
		},
	}

	tpEnableCmd := &cobra.Command{
		Use:   "enable <name>",
		Short: "enable a tracing policy",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			common.CliRun(func(ctx context.Context, cli tetragon.FineGuidanceSensorsClient) {
				enableTracingPolicy(ctx, cli, args[0])
			})
		},
	}

	tpDisableCmd := &cobra.Command{
		Use:   "disable <name>",
		Short: "disable a tracing policy",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			common.CliRun(func(ctx context.Context, cli tetragon.FineGuidanceSensorsClient) {
				disableTracingPolicy(ctx, cli, args[0])
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

	tpCmd.AddCommand(tpAddCmd, tpDelCmd, tpEnableCmd, tpDisableCmd, tpListCmd, generate.New())
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

func enableTracingPolicy(ctx context.Context, client tetragon.FineGuidanceSensorsClient, name string) {
	_, err := client.EnableTracingPolicy(ctx, &tetragon.EnableTracingPolicyRequest{
		Name: name,
	})
	if err != nil {
		fmt.Printf("failed to enable tracing policy: %s\n", err)
	}
}

func disableTracingPolicy(ctx context.Context, client tetragon.FineGuidanceSensorsClient, name string) {
	_, err := client.DisableTracingPolicy(ctx, &tetragon.DisableTracingPolicyRequest{
		Name: name,
	})
	if err != nil {
		fmt.Printf("failed to disable tracing policy: %s\n", err)
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
