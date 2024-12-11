// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package tracingpolicy

import (
	"fmt"
	"os"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/cmd/tetra/common"
	"github.com/cilium/tetragon/cmd/tetra/tracingpolicy/generate"
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
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := common.NewClientWithDefaultContextAndAddress()
			if err != nil {
				return fmt.Errorf("failed create gRPC client: %w", err)
			}
			defer c.Close()

			yamlb, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("failed to read yaml file %s: %w", args[0], err)
			}

			_, err = c.Client.AddTracingPolicy(c.Ctx, &tetragon.AddTracingPolicyRequest{
				Yaml: string(yamlb),
			})
			if err != nil {
				return fmt.Errorf("failed to add tracing policy: %w", err)
			}
			cmd.Printf("tracing policy %q added\n", args[0])

			return nil
		},
	}

	var tpDelNamespaceFlag string
	tpDelCmd := &cobra.Command{
		Use:   "delete <name>",
		Short: "delete a tracing policy",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := common.NewClientWithDefaultContextAndAddress()
			if err != nil {
				return fmt.Errorf("failed create gRPC client: %w", err)
			}
			defer c.Close()

			_, err = c.Client.DeleteTracingPolicy(c.Ctx, &tetragon.DeleteTracingPolicyRequest{
				Name:      args[0],
				Namespace: tpDelNamespaceFlag,
			})
			if err != nil {
				return fmt.Errorf("failed to delete tracing policy: %w", err)
			}
			cmd.Printf("tracing policy %q deleted\n", args[0])

			return nil
		},
	}

	var tpEnableNamespaceFlag string
	tpEnableCmd := &cobra.Command{
		Use:   "enable <name>",
		Short: "enable a tracing policy",
		Long:  "Enable a disabled tracing policy. Use disable to re-disable the tracing policy.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := common.NewClientWithDefaultContextAndAddress()
			if err != nil {
				return fmt.Errorf("failed create gRPC client: %w", err)
			}
			defer c.Close()

			_, err = c.Client.EnableTracingPolicy(c.Ctx, &tetragon.EnableTracingPolicyRequest{
				Name:      args[0],
				Namespace: tpEnableNamespaceFlag,
			})
			if err != nil {
				return fmt.Errorf("failed to enable tracing policy: %w", err)
			}
			cmd.Printf("tracing policy %q enabled\n", args[0])

			return nil
		},
	}

	var tpDisableNamespaceFlag string
	tpDisableCmd := &cobra.Command{
		Use:   "disable <name>",
		Short: "disable a tracing policy",
		Long:  "Disable an enabled tracing policy. Use enable to re-enable the tracing policy.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := common.NewClientWithDefaultContextAndAddress()
			if err != nil {
				return fmt.Errorf("failed create gRPC client: %w", err)
			}
			defer c.Close()

			_, err = c.Client.DisableTracingPolicy(c.Ctx, &tetragon.DisableTracingPolicyRequest{
				Name:      args[0],
				Namespace: tpDisableNamespaceFlag,
			})

			if err != nil {
				return fmt.Errorf("failed to disable tracing policy: %w", err)
			}

			cmd.Printf("tracing policy %q disabled\n", args[0])

			return nil
		},
	}

	var tpListOutputFlag string
	tpListCmd := &cobra.Command{
		Use:   "list",
		Short: "list loaded tracing policies",
		Long:  "List loaded tracing policies, use the JSON output format for full output.",
		Args:  cobra.ExactArgs(0),
		PreRunE: func(_ *cobra.Command, _ []string) error {
			if tpListOutputFlag != "json" && tpListOutputFlag != "text" {
				return fmt.Errorf("invalid value for %q flag: %s", common.KeyOutput, tpListOutputFlag)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := common.NewClientWithDefaultContextAndAddress()
			if err != nil {
				return fmt.Errorf("failed create gRPC client: %w", err)
			}
			defer c.Close()

			res, err := c.Client.ListTracingPolicies(c.Ctx, &tetragon.ListTracingPoliciesRequest{})
			if err != nil || res == nil {
				return fmt.Errorf("failed to list tracing policies: %w", err)
			}

			switch tpListOutputFlag {
			case "json":
				b, err := res.MarshalJSON()
				if err != nil {
					return fmt.Errorf("failed to generate json: %w", err)
				}
				cmd.Println(string(b))
			case "text":
				common.PrintTracingPolicies(cmd.OutOrStdout(), res.Policies, nil)
			}

			return nil
		},
	}
	tpDelFlags := tpDelCmd.Flags()
	tpDelFlags.StringVarP(&tpDelNamespaceFlag, common.KeyNamespace, "n", "", "Namespace of the tracing policy.")
	tpEnableFlags := tpEnableCmd.Flags()
	tpEnableFlags.StringVarP(&tpEnableNamespaceFlag, common.KeyNamespace, "n", "", "Namespace of the tracing policy.")
	tpDisableFlags := tpDisableCmd.Flags()
	tpDisableFlags.StringVarP(&tpDisableNamespaceFlag, common.KeyNamespace, "n", "", "Namespace of the tracing policy.")
	tpListFlags := tpListCmd.Flags()
	tpListFlags.StringVarP(&tpListOutputFlag, common.KeyOutput, "o", "text", "Output format. text or json")

	tpCmd.AddCommand(
		tpAddCmd,
		tpDelCmd,
		tpEnableCmd,
		tpDisableCmd,
		tpListCmd,
		generate.New(),
	)

	return tpCmd
}
