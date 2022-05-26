// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package config

import (
	"context"
	"fmt"

	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

func mergeSensors(sens []*sensors.Sensor) *sensors.Sensor {
	var progs []*program.Program
	var maps []*program.Map

	for _, s := range sens {
		progs = append(progs, s.Progs...)
		maps = append(maps, s.Maps...)
	}
	return &sensors.Sensor{
		Name:  "__main__",
		Progs: progs,
		Maps:  maps,
	}
}

// LoadConfig loads the default sensor, including any from the configuration file.
func LoadConfig(ctx context.Context, bpfDir, mapDir, ciliumDir string, s []*sensors.Sensor) error {
	load := mergeSensors(s)

	if err := load.Load(ctx, bpfDir, mapDir, ciliumDir); err != nil {
		return fmt.Errorf("tetragon, aborting could not load BPF programs: %w", err)
	}

	return nil
}
