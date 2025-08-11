// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package sensors

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/cmd/tetra/common"
)

// Let's deprecated and remove this sensor interface and use the tracing policy
// gRPCs. Those are accessible trough the tracingpolicy command.
func New() *cobra.Command {
	sensorsCmd := &cobra.Command{
		Use:        "sensors",
		Short:      "Manage sensors",
		Deprecated: "please use the tracingpolicy command instead.",
	}

	sensorsListCmd := &cobra.Command{
		Use:   "list",
		Short: "List available sensors",
		Run: func(_ *cobra.Command, _ []string) {
			common.CliRun(listSensors)
		},
	}
	sensorsCmd.AddCommand(sensorsListCmd)

	sensorEnableCmd := &cobra.Command{
		Use:   "enable <sensor>",
		Short: "Enable sensor",
		Args:  cobra.ExactArgs(1),
		Run: func(_ *cobra.Command, args []string) {
			sensor := args[0]
			common.CliRun(func(ctx context.Context, cli tetragon.FineGuidanceSensorsClient) {
				enableSensor(ctx, cli, sensor)
			})
		},
	}
	sensorsCmd.AddCommand(sensorEnableCmd)

	sensorDisableCmd := &cobra.Command{
		Use:   "disable <sensor>",
		Short: "Disable sensor",
		Args:  cobra.ExactArgs(1),
		Run: func(_ *cobra.Command, args []string) {
			sensor := args[0]
			common.CliRun(func(ctx context.Context, cli tetragon.FineGuidanceSensorsClient) {
				disableSensor(ctx, cli, sensor)
			})
		},
	}
	sensorsCmd.AddCommand(sensorDisableCmd)

	sensorRmCmd := &cobra.Command{
		Use:   "rm <sensor_name>",
		Short: "remove a sensor",
		Args:  cobra.ExactArgs(1),
		Run: func(_ *cobra.Command, args []string) {
			common.CliRun(func(ctx context.Context, cli tetragon.FineGuidanceSensorsClient) {
				removeSensor(ctx, cli, args[0])
			})
		},
	}
	sensorsCmd.AddCommand(sensorRmCmd)

	return sensorsCmd
}

func listSensors(ctx context.Context, client tetragon.FineGuidanceSensorsClient) {
	// ignore deprecation warnings
	//nolint:staticcheck
	sensors, err := client.ListSensors(ctx, &tetragon.ListSensorsRequest{})
	if err != nil {
		fmt.Printf("error: %s\n", err)
		return
	} else if sensors == nil {
		fmt.Printf("error: sensors is nil\n")
		return
	}

	for _, sensor := range sensors.Sensors {
		enabled := ""
		if sensor.Enabled {
			enabled = "(enabled)"
		} else {
			enabled = "(not enabled)"
		}
		fmt.Printf("%s %s %s\n", sensor.Name, enabled, sensor.Collection)
	}
}

func removeSensor(ctx context.Context, client tetragon.FineGuidanceSensorsClient, sensor string) {
	// ignore deprecation warnings
	//nolint:staticcheck
	_, err := client.RemoveSensor(ctx, &tetragon.RemoveSensorRequest{
		Name: sensor,
	})
	if err != nil {
		fmt.Printf("failed to remove tracing policy: %s\n", err)
	}
}

func enableSensor(ctx context.Context, client tetragon.FineGuidanceSensorsClient, sensor string) {
	// ignore deprecation warnings
	//nolint:staticcheck
	_, err := client.EnableSensor(ctx, &tetragon.EnableSensorRequest{Name: sensor})
	if err == nil {
		fmt.Printf("sensor %s enabled\n", sensor)
	} else {
		fmt.Printf("failed to enable sensor %s: %s\n", sensor, err)
	}
}

func disableSensor(ctx context.Context, client tetragon.FineGuidanceSensorsClient, sensor string) {
	// ignore deprecation warnings
	//nolint:staticcheck
	_, err := client.DisableSensor(ctx, &tetragon.DisableSensorRequest{Name: sensor})
	if err == nil {
		fmt.Printf("sensor %s disabled\n", sensor)
	} else {
		fmt.Printf("failed to disable sensor %s: %s\n", sensor, err)
	}
}
