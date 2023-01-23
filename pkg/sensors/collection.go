// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package sensors

import (
	"context"
	"fmt"

	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"go.uber.org/multierr"
)

// collection is a collection of sensors
// This can either be creating from a tracing policy, or by loading sensors indepenently for sensors
// that are not loaded via a tracing policy (e.g., base sensor) and testing.
type collection struct {
	sensors       []*Sensor
	name          string
	tracingpolicy tracingpolicy.TracingPolicy
}

func (c *collection) info() string {
	if c.tracingpolicy != nil {
		return c.tracingpolicy.TpInfo()
	}
	return c.name
}

// load will attempt to load a collection of sensors. If loading one of the sensors fails, it
// will attempt to unload the already loaded sensors.
func (c *collection) load(ctx context.Context, bpfDir, mapDir, ciliumDir string, cbArg *LoadArg) error {

	var err error
	for _, sensor := range c.sensors {
		if sensor.Loaded {
			// NB: For now, we don't treat a sensor already loaded as an error
			// because that would complicate things.
			continue
		}
		if err = sensor.FindPrograms(ctx); err != nil {
			err = fmt.Errorf("sensor %s programs from collection %s could not be found: %s", sensor.Name, c.name, err)
			break
		}

		if err = sensor.Load(ctx, bpfDir, mapDir, ciliumDir); err != nil {
			err = fmt.Errorf("sensor %s from collection %s failed to load: %s", sensor.Name, c.name, err)
			break
		}
	}

	// if there was an error, try to unload all the sensors
	if err != nil {
		// NB: we could try to unload sensors going back from the one that failed, but since
		// unload() checks s.Loaded, is easier to just to use unload().
		if unloadErr := c.unload(nil); unloadErr != nil {
			err = multierr.Append(err, fmt.Errorf("unloading after loading failure failed: %w", unloadErr))
		}
	} else {
		// otherwise, call the loaded callbalcks for all the sensors
		if cbArg != nil {
			for _, sensor := range c.sensors {
				if sensor.Ops != nil {
					sensor.Ops.Loaded(*cbArg)
				}
			}
		}
	}

	return err
}

// unload will attempt to unload all the sensors in a collection
func (c *collection) unload(cbArg *UnloadArg) error {
	var err error
	for _, s := range c.sensors {
		if !s.Loaded {
			continue
		}
		unloadErr := s.Unload()
		if unloadErr == nil && cbArg != nil && s.Ops != nil {
			s.Ops.Unloaded(*cbArg)
		}
		err = multierr.Append(err, unloadErr)
	}

	if err != nil {
		err = fmt.Errorf("failed to unload all sensors from collection %s: %w", c.name, err)
	}
	return err
}
