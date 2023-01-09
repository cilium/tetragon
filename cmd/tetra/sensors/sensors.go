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

package sensors

import (
	"context"
	"fmt"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/cmd/tetra/common"
	"github.com/spf13/cobra"
)

func New() *cobra.Command {
	sensorsCmd := &cobra.Command{
		Use:   "sensors",
		Short: "Manage sensors",
	}

	sensorsListCmd := &cobra.Command{
		Use:   "list",
		Short: "List available sensors",
		Run: func(cmd *cobra.Command, args []string) {
			common.CliRun(listSensors)
		},
	}
	sensorsCmd.AddCommand(sensorsListCmd)

	sensorEnableCmd := &cobra.Command{
		Use:   "enable <sensor>",
		Short: "Enable sensor",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
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
		Run: func(cmd *cobra.Command, args []string) {
			sensor := args[0]
			common.CliRun(func(ctx context.Context, cli tetragon.FineGuidanceSensorsClient) {
				disableSensor(ctx, cli, sensor)
			})
		},
	}
	sensorsCmd.AddCommand(sensorDisableCmd)

	sensorConfigCmd := &cobra.Command{
		Use:   "config <sensor> [param] [val]",
		Short: "Configure sensor",
		Args:  cobra.RangeArgs(1, 3),
		Run: func(cmd *cobra.Command, args []string) {
			sensor := args[0]
			switch len(args) {
			case 1:
				common.CliRun(func(ctx context.Context, cli tetragon.FineGuidanceSensorsClient) {
					sensorGetConfig(ctx, cli, sensor, "")
				})
			case 2:
				common.CliRun(func(ctx context.Context, cli tetragon.FineGuidanceSensorsClient) {
					sensorGetConfig(ctx, cli, sensor, args[1])
				})
			case 3:
				common.CliRun(func(ctx context.Context, cli tetragon.FineGuidanceSensorsClient) {
					sensorSetConfig(ctx, cli, sensor, args[1], args[2])
				})
			}
		},
	}
	sensorsCmd.AddCommand(sensorConfigCmd)

	sensorRmCmd := &cobra.Command{
		Use:   "rm <sensor_name>",
		Short: "remove a sensor",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			common.CliRun(func(ctx context.Context, cli tetragon.FineGuidanceSensorsClient) {
				removeSensor(ctx, cli, args[0])
			})
		},
	}
	sensorsCmd.AddCommand(sensorRmCmd)

	return sensorsCmd
}

func listSensors(ctx context.Context, client tetragon.FineGuidanceSensorsClient) {
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
	_, err := client.RemoveSensor(ctx, &tetragon.RemoveSensorRequest{
		Name: sensor,
	})
	if err != nil {
		fmt.Printf("failed to remove tracing policy: %s\n", err)
	}
}

func enableSensor(ctx context.Context, client tetragon.FineGuidanceSensorsClient, sensor string) {
	_, err := client.EnableSensor(ctx, &tetragon.EnableSensorRequest{Name: sensor})
	if err == nil {
		fmt.Printf("sensor %s enabled\n", sensor)
	} else {
		fmt.Printf("failed to enable sensor %s: %s\n", sensor, err)
	}
}

func disableSensor(ctx context.Context, client tetragon.FineGuidanceSensorsClient, sensor string) {
	_, err := client.DisableSensor(ctx, &tetragon.DisableSensorRequest{Name: sensor})
	if err == nil {
		fmt.Printf("sensor %s disabled\n", sensor)
	} else {
		fmt.Printf("failed to disable sensor %s: %s\n", sensor, err)
	}
}

func sensorGetConfig(ctx context.Context, client tetragon.FineGuidanceSensorsClient, sensor string, cfgkey string) {
	req := tetragon.GetSensorConfigRequest{Name: sensor, Cfgkey: cfgkey}
	res, err := client.GetSensorConfig(ctx, &req)
	if err == nil {
		fmt.Printf("%s\n", res.Cfgval)
	} else {
		fmt.Printf("error getting %s config value for %s: %s\n", cfgkey, sensor, err)
	}
}

func sensorSetConfig(ctx context.Context, client tetragon.FineGuidanceSensorsClient, sensor string, cfgkey string, cfgval string) {
	req := tetragon.SetSensorConfigRequest{Name: sensor, Cfgkey: cfgkey, Cfgval: cfgval}
	_, err := client.SetSensorConfig(ctx, &req)
	if err != nil {
		fmt.Printf("error setting %s=%s config for %s: %s\n", cfgkey, cfgval, sensor, err)
	}
}
