// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package loglevel

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/cmd/tetra/common"
	"github.com/cilium/tetragon/pkg/logger"
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

			currentLoglevel, err := c.Client.GetDebug(c.Ctx, &tetragon.GetDebugRequest{
				Flag: tetragon.ConfigFlag_CONFIG_FLAG_LOG_LEVEL,
			})
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
				return errors.New("usage: tetra loglevel set [trace|debug|info|warning|error|fatal|panic]")
			}
			levelStr := args[0]
			levelParsed, err := logger.ParseLevel(levelStr)
			if err != nil {
				return fmt.Errorf("invalid log level: %s", levelStr)
			}

			c, err := common.NewClientWithDefaultContextAndAddress()
			if err != nil {
				return fmt.Errorf("failed create gRPC client: %w", err)
			}
			defer c.Close()

			var logLevel tetragon.LogLevel
			switch levelParsed {
			case logger.LevelTrace:
				logLevel = tetragon.LogLevel_LOG_LEVEL_TRACE
			case slog.LevelDebug:
				logLevel = tetragon.LogLevel_LOG_LEVEL_DEBUG
			case slog.LevelInfo:
				logLevel = tetragon.LogLevel_LOG_LEVEL_INFO
			case slog.LevelWarn:
				logLevel = tetragon.LogLevel_LOG_LEVEL_WARN
			case slog.LevelError:
				logLevel = tetragon.LogLevel_LOG_LEVEL_ERROR
			case logger.LevelPanic:
				logLevel = tetragon.LogLevel_LOG_LEVEL_PANIC
			case logger.LevelFatal:
				logLevel = tetragon.LogLevel_LOG_LEVEL_FATAL
			default:
				logLevel = tetragon.LogLevel_LOG_LEVEL_INFO
			}
			currentLogLevel, err := c.Client.SetDebug(c.Ctx, &tetragon.SetDebugRequest{
				Flag: tetragon.ConfigFlag_CONFIG_FLAG_LOG_LEVEL,
				Arg: &tetragon.SetDebugRequest_Level{
					Level: logLevel,
				},
			})
			if err != nil {
				return fmt.Errorf("failed to set log level: %w", err)
			}
			cmd.Printf("Log level set to: %s\n", currentLogLevel.GetLevel())

			return nil
		},
	}

	// Add subcommands to the main command
	cmd.AddCommand(
		getCmd,
		setCmd,
	)

	return cmd
}
