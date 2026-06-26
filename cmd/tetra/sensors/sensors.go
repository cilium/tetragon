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
		RunE: func(_ *cobra.Command, _ []string) error {
			c, err := common.NewClientWithDefaultContextAndAddress()
			if err != nil {
				return err
			}
			defer c.Close()
			return listSensors(c.Ctx, c.Client)
		},
	}
	sensorsCmd.AddCommand(sensorsListCmd)

	sensorEnableCmd := &cobra.Command{
		Use:   "enable <sensor>",
		Short: "Enable sensor",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			c, err := common.NewClientWithDefaultContextAndAddress()
			if err != nil {
				return err
			}
			defer c.Close()
			return enableSensor(c.Ctx, c.Client, args[0])
		},
	}
	sensorsCmd.AddCommand(sensorEnableCmd)

	sensorDisableCmd := &cobra.Command{
		Use:   "disable <sensor>",
		Short: "Disable sensor",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			c, err := common.NewClientWithDefaultContextAndAddress()
			if err != nil {
				return err
			}
			defer c.Close()
			return disableSensor(c.Ctx, c.Client, args[0])
		},
	}
	sensorsCmd.AddCommand(sensorDisableCmd)

	sensorRmCmd := &cobra.Command{
		Use:   "rm <sensor_name>",
		Short: "remove a sensor",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			c, err := common.NewClientWithDefaultContextAndAddress()
			if err != nil {
				return err
			}
			defer c.Close()
			return removeSensor(c.Ctx, c.Client, args[0])
		},
	}
	sensorsCmd.AddCommand(sensorRmCmd)

	return sensorsCmd
}

func listSensors(ctx context.Context, client tetragon.FineGuidanceSensorsClient) error {
	// ignore deprecation warnings
	//nolint:staticcheck
	sensors, err := client.ListSensors(ctx, &tetragon.ListSensorsRequest{})
	if err != nil {
		return fmt.Errorf("failed to list sensors: %w", err)
	}
	if sensors == nil {
		return fmt.Errorf("sensors is nil")
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
	return nil
}

func removeSensor(ctx context.Context, client tetragon.FineGuidanceSensorsClient, sensor string) error {
	// ignore deprecation warnings
	//nolint:staticcheck
	_, err := client.RemoveSensor(ctx, &tetragon.RemoveSensorRequest{
		Name: sensor,
	})
	if err != nil {
		return fmt.Errorf("failed to remove sensor: %w", err)
	}
	return nil
}

func enableSensor(ctx context.Context, client tetragon.FineGuidanceSensorsClient, sensor string) error {
	// ignore deprecation warnings
	//nolint:staticcheck
	_, err := client.EnableSensor(ctx, &tetragon.EnableSensorRequest{Name: sensor})
	if err != nil {
		return fmt.Errorf("failed to enable sensor %s: %w", sensor, err)
	}
	fmt.Printf("sensor %s enabled\n", sensor)
	return nil
}

func disableSensor(ctx context.Context, client tetragon.FineGuidanceSensorsClient, sensor string) error {
	// ignore deprecation warnings
	//nolint:staticcheck
	_, err := client.DisableSensor(ctx, &tetragon.DisableSensorRequest{Name: sensor})
	if err != nil {
		return fmt.Errorf("failed to disable sensor %s: %w", sensor, err)
	}
	fmt.Printf("sensor %s disabled\n", sensor)
	return nil
}
