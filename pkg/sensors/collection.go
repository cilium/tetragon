// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package sensors

import (
	"fmt"

	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"go.uber.org/multierr"
)

// collection is a collection of sensors
// This can either be creating from a tracing policy, or by loading sensors indepenently for sensors
// that are not loaded via a tracing policy (e.g., base sensor) and testing.
type collection struct {
	sensors []*Sensor
	name    string
	err     error
	// fields below are only set for tracing policies
	tracingpolicy   tracingpolicy.TracingPolicy
	tracingpolicyID uint64
	// if this is not zero, then the policy is filtered
	policyfilterID uint64
}

func (c *collection) info() string {
	if c.tracingpolicy != nil {
		return c.tracingpolicy.TpInfo()
	}
	return c.name
}

// load will attempt to load a collection of sensors. If loading one of the sensors fails, it
// will attempt to unload the already loaded sensors.
func (c *collection) load(bpfDir, mapDir string) error {

	var err error
	for _, sensor := range c.sensors {
		if sensor.Loaded {
			// NB: For now, we don't treat a sensor already loaded as an error
			// because that would complicate things.
			continue
		}
		if err = sensor.FindPrograms(); err != nil {
			err = fmt.Errorf("sensor %s programs from collection %s could not be found: %s", sensor.Name, c.name, err)
			break
		}

		if err = sensor.Load(bpfDir, mapDir); err != nil {
			err = fmt.Errorf("sensor %s from collection %s failed to load: %s", sensor.Name, c.name, err)
			break
		}
	}

	// if there was an error, try to unload all the sensors
	if err != nil {
		// NB: we could try to unload sensors going back from the one that failed, but since
		// unload() checks s.Loaded, is easier to just to use unload().
		if unloadErr := c.unload(); unloadErr != nil {
			err = multierr.Append(err, fmt.Errorf("unloading after loading failure failed: %w", unloadErr))
		}
	}

	return err
}

// unload will attempt to unload all the sensors in a collection
func (c *collection) unload() error {
	var err error
	for _, s := range c.sensors {
		if !s.Loaded {
			continue
		}
		unloadErr := s.Unload()
		err = multierr.Append(err, unloadErr)
	}

	if err != nil {
		return fmt.Errorf("failed to unload all sensors from collection %s: %w", c.name, err)
	}
	return nil
}
