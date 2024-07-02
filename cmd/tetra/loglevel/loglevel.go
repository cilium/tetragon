// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package loglevel

import (
	"fmt"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/cmd/tetra/common"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "loglevel",
		Aliases: []string{"log"},
		Short:   "Get and dynamically change the log level",
		Long:    `This command allows it to dynamically change the log level without restarting Tetragon`,
	}

	getCmd := &cobra.Command{
		Use:   "get",
		Short: "Prints the current log level",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := common.NewClientWithDefaultContextAndAddress()
			if err != nil {
				return fmt.Errorf("failed create gRPC client: %w", err)
			}
			defer c.Close()

			currentLoglevel, err := c.Client.GetLogLevel(c.Ctx, &tetragon.GetLogLevelRequest{})
			if err != nil {
				return fmt.Errorf("failed to get current Tetragon log level: %w", err)
			}
			cmd.Printf("Current log level: %s\n", currentLoglevel.GetLevel())

			return nil
		},
	}

	setCmd := &cobra.Command{
		Use:   "set",
		Short: "Set the log level",
		Long: `Allowed values are [trace|debug|info|warning|error|fatal|panic]. Examples:
	
	  # Set the log level to debug
	  tetra loglevel set debug
	
	  # Set the log level to info
	  tetra loglevel set info`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("usage: tetra loglevel set [trace|debug|info|warning|error|fatal|panic]")
			}
			levelStr := args[0]
			_, err := logrus.ParseLevel(levelStr)
			if err != nil {
				return fmt.Errorf("invalid log level: %s", levelStr)
			}

			c, err := common.NewClientWithDefaultContextAndAddress()
			if err != nil {
				return fmt.Errorf("failed create gRPC client: %w", err)
			}
			defer c.Close()

			currentLogLevel, err := c.Client.SetLogLevel(c.Ctx, &tetragon.SetLogLevelRequest{
				Level: levelStr,
			})
			if err != nil {
				return fmt.Errorf("failed to set log level: %w", err)
			}
			cmd.Printf("Log level set to: %s\n", currentLogLevel.GetLevel())

			return nil
		},
	}

	resetCmd := &cobra.Command{
		Use:   "reset",
		Short: "Reset the log level to the value Tetragon was started with",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := common.NewClientWithDefaultContextAndAddress()
			if err != nil {
				return fmt.Errorf("failed create gRPC client: %w", err)
			}
			defer c.Close()

			currentLogLevel, err := c.Client.ResetLogLevel(c.Ctx, &tetragon.ResetLogLevelRequest{})
			if err != nil {
				return fmt.Errorf("failed to reset log level: %w", err)
			}
			cmd.Printf("Reset log level to: %s\n", currentLogLevel.GetLevel())

			return nil
		},
	}

	// Add subcommands to the main command
	cmd.AddCommand(
		getCmd,
		setCmd,
		resetCmd,
	)

	return cmd
}
