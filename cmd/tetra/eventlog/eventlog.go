// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package eventlog

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

func setCmd() *cobra.Command {
	var (
		maxSizeVar          int32
		maxBackupsVar       int32
		rotationIntervalVar time.Duration
	)
	cmd := &cobra.Command{
		Use:   "set",
		Short: "set logging parameters",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := NewClient()
			if err != nil {
				return fmt.Errorf("failed to create gRPC client: %w", err)
			}
			defer c.Close()

			var (
				interval   *string
				maxSize    *int32
				maxBackups *int32
			)
			if cmd.Flags().Lookup("max-size").Changed {
				maxSize = &maxSizeVar
			}
			if cmd.Flags().Lookup("max-backups").Changed {
				maxBackups = &maxBackupsVar
			}
			if cmd.Flags().Lookup("rotation-interval").Changed {
				strVal := rotationIntervalVar.String()
				interval = &strVal
			}
			_, err = c.Client.SetEventLogParams(c.ctx, &tetragon.SetEventLogParamsRequest{
				MaxSize:          maxSize,
				RotationInterval: interval,
				MaxBackups:       maxBackups,
			})
			return err
		},
	}

	flags := cmd.Flags()
	flags.Int32Var(&maxSizeVar, "max-size", 0, "log files maximum size")
	flags.Int32Var(&maxBackupsVar, "max-backups", 0, "maximum rotated log files to be retained")
	flags.DurationVar(&rotationIntervalVar, "rotation-interval", 0, "log files rotation interval")
	viper.BindPFlags(flags)
	return cmd
}

func getCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get",
		Short: "get logging parameters",
		Args:  cobra.ExactArgs(0),
		RunE: func(_ *cobra.Command, _ []string) error {
			c, err := NewClient()
			if err != nil {
				return fmt.Errorf("failed to create gRPC client: %w", err)
			}
			defer c.Close()

			params, err := c.Client.GetEventLogParams(c.ctx, &tetragon.GetEventLogParamsRequest{})
			if err != nil {
				return err
			}
			fmt.Printf("Current logging parameters: %+v\n", params)
			return nil
		},
	}
	return cmd
}

func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "eventlog",
		Short: "Manage event exporter logging parameters",
	}

	cmd.AddCommand(
		setCmd(),
		getCmd(),
	)

	return cmd
}
