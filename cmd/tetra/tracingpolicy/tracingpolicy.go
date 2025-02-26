// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

//go:build !windows

package tracingpolicy

import (
	"fmt"
	"os"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/cmd/tetra/common"
	"github.com/cilium/tetragon/cmd/tetra/tracingpolicy/generate"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/spf13/cobra"
)

func tpConfigure(name, namespace string, enable *bool, mode *tetragon.TracingPolicyMode) error {
	c, err := common.NewClientWithDefaultContextAndAddress()
	if err != nil {
		return fmt.Errorf("failed create gRPC client: %w", err)
	}
	defer c.Close()

	_, err = c.Client.ConfigureTracingPolicy(c.Ctx, &tetragon.ConfigureTracingPolicyRequest{
		Name:      name,
		Namespace: namespace,
		Enable:    enable,
		Mode:      mode,
	})
	return err
}

func tpModifyCmd() *cobra.Command {
	var mode string
	ret := &cobra.Command{
		Use:   "modify <yaml_file>",
		Short: "modify a tracing policy YAML file",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			c, err := common.NewClientWithDefaultContextAndAddress()
			if err != nil {
				return fmt.Errorf("failed create gRPC client: %w", err)
			}
			defer c.Close()

			yamlb, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("failed to read yaml file %s: %w", args[0], err)
			}

			if mode != "" {
				yamlb, err = tracingpolicy.PolicyYAMLSetMode(yamlb, mode)
				if err != nil {
					return fmt.Errorf("failed to apply mode %q to yaml file %s: %w", mode, args[0], err)
				}
			}
			_, err = os.Stdout.Write(yamlb)
			return err
		},
	}
	flags := ret.Flags()
	flags.StringVarP(&mode, "mode", "m", "", "Tracing policy mode (enforce|monitor)")
	return ret
}

func tpAddCmd() *cobra.Command {
	var mode string
	ret := &cobra.Command{
		Use:   "add <yaml_file>",
		Short: "add a tracing policy",
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

			if mode != "" {
				yamlb, err = tracingpolicy.PolicyYAMLSetMode(yamlb, mode)
				if err != nil {
					return fmt.Errorf("failed to apply mode %q to yaml file %s: %w", mode, args[0], err)
				}
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
	flags := ret.Flags()
	flags.StringVarP(&mode, "mode", "m", "", "Tracing policy mode (enforce|monitor)")
	return ret
}

func tpDelCmd() *cobra.Command {
	var namespace string
	ret := &cobra.Command{
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
				Namespace: namespace,
			})
			if err != nil {
				return fmt.Errorf("failed to delete tracing policy: %w", err)
			}
			cmd.Printf("tracing policy %q deleted\n", args[0])

			return nil
		},
	}
	flags := ret.Flags()
	flags.StringVarP(&namespace, common.KeyNamespace, "n", "", "Namespace of the tracing policy.")
	return ret
}

func tpEnableCmd() *cobra.Command {
	var namespace string
	ret := &cobra.Command{
		Use:   "enable <name>",
		Short: "enable a tracing policy",
		Long:  "Enable a disabled tracing policy. Use disable to re-disable the tracing policy.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			enable := true
			err := tpConfigure(args[0], namespace, &enable, nil)
			if err != nil {
				return fmt.Errorf("failed to enable tracing policy: %w", err)
			}
			cmd.Printf("tracing policy %q enabled\n", args[0])
			return nil
		},
	}
	flags := ret.Flags()
	flags.StringVarP(&namespace, common.KeyNamespace, "n", "", "Namespace of the tracing policy.")
	return ret
}

func tpDisableCmd() *cobra.Command {
	var namespace string
	ret := &cobra.Command{
		Use:   "disable <name>",
		Short: "disable a tracing policy",
		Long:  "Disable an enabled tracing policy. Use enable to re-enable the tracing policy.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			enable := false
			err := tpConfigure(args[0], namespace, &enable, nil)
			if err != nil {
				return fmt.Errorf("failed to disable tracing policy: %w", err)
			}
			cmd.Printf("tracing policy %q disabled\n", args[0])
			return nil
		},
	}

	flags := ret.Flags()
	flags.StringVarP(&namespace, common.KeyNamespace, "n", "", "Namespace of the tracing policy.")
	return ret
}

func tpListCmd() *cobra.Command {
	var output string
	ret := &cobra.Command{
		Use:   "list",
		Short: "list loaded tracing policies",
		Long:  "List loaded tracing policies, use the JSON output format for full output.",
		Args:  cobra.ExactArgs(0),
		PreRunE: func(_ *cobra.Command, _ []string) error {
			if output != "json" && output != "text" {
				return fmt.Errorf("invalid value for %q flag: %s", common.KeyOutput, output)
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

			switch output {
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
	flags := ret.Flags()
	flags.StringVarP(&output, common.KeyOutput, "o", "text", "Output format. text or json")
	return ret
}

func tpSetModeCmd() *cobra.Command {
	var namespace string
	ret := &cobra.Command{
		Use:   "set-mode <name> <mode>",
		Short: "set the mode of a tracing policy",
		Long:  "Set a tracing policy to monitor or enforce mode.",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {

			var mode tetragon.TracingPolicyMode
			switch args[1] {
			case "enforce":
				mode = tetragon.TracingPolicyMode_TP_MODE_ENFORCE
			case "monitor":
				mode = tetragon.TracingPolicyMode_TP_MODE_MONITOR
			default:
				return fmt.Errorf("invalid mode %q", args[1])
			}

			err := tpConfigure(args[0], namespace, nil, &mode)
			if err != nil {
				return fmt.Errorf("failed set mode to %q tracing policy: %w", args[1], err)
			}
			cmd.Printf("tracing policy %q set to mode %q\n", args[0], args[1])
			return nil
		},
	}

	flags := ret.Flags()
	flags.StringVarP(&namespace, common.KeyNamespace, "n", "", "Namespace of the tracing policy.")
	return ret
}

func New() *cobra.Command {
	tpCmd := &cobra.Command{
		Use:     "tracingpolicy",
		Aliases: []string{"tp"},
		Short:   "Manage tracing policies",
	}

	tpCmd.AddCommand(
		tpModifyCmd(),
		tpAddCmd(),
		tpDelCmd(),
		tpEnableCmd(),
		tpDisableCmd(),
		tpListCmd(),
		tpSetModeCmd(),
		generate.New(),
	)

	return tpCmd
}
