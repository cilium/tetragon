// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package sensors

import (
	"errors"
	"fmt"
	"sync"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/policyconf"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"go.uber.org/multierr"
)

type TracingPolicyState int

const (
	UnknownState TracingPolicyState = iota
	EnabledState
	DisabledState
	LoadErrorState
	ErrorState
	LoadingState
	UnloadingState
)

func (s TracingPolicyState) ToTetragonState() tetragon.TracingPolicyState {
	switch s {
	case EnabledState:
		return tetragon.TracingPolicyState_TP_STATE_ENABLED
	case DisabledState:
		return tetragon.TracingPolicyState_TP_STATE_DISABLED
	case LoadErrorState:
		return tetragon.TracingPolicyState_TP_STATE_LOAD_ERROR
	case ErrorState:
		return tetragon.TracingPolicyState_TP_STATE_ERROR
	case LoadingState:
		return tetragon.TracingPolicyState_TP_STATE_LOADING
	case UnloadingState:
		return tetragon.TracingPolicyState_TP_STATE_UNLOADING
	default:
		return tetragon.TracingPolicyState_TP_STATE_UNKNOWN
	}
}

// collectionKey is the unique key for sensors
// this enables policies with the same name for different namespaces
type collectionKey struct {
	name, namespace string
}

func (ck *collectionKey) String() string {
	if ck.namespace != "" {
		return fmt.Sprintf("%s/%s", ck.namespace, ck.name)
	}
	return ck.name
}

// collection is a collection of sensors
// This can either be creating from a tracing policy, or by loading sensors indepenently for sensors
// that are not loaded via a tracing policy (e.g., base sensor) and testing.
type collection struct {
	sensors []SensorIface
	name    string
	err     error
	// fields below are only set for tracing policies
	tracingpolicy   tracingpolicy.TracingPolicy
	tracingpolicyID uint64
	// if this is not zero, then the policy is filtered
	policyfilterID uint64
	// state indicates the state of the collection
	state TracingPolicyState
}

type collectionMap struct {
	// map of sensor collections: name, namespace -> collection
	c  map[collectionKey]*collection
	mu sync.RWMutex
}

func newCollectionMap() *collectionMap {
	return &collectionMap{
		c: map[collectionKey]*collection{},
	}
}

func (c *collection) info() string {
	if c.tracingpolicy != nil {
		return c.tracingpolicy.TpInfo()
	}
	return c.name
}

func (c *collection) mode() tetragon.TracingPolicyMode {
	if c.tracingpolicy == nil || c.state != EnabledState {
		return tetragon.TracingPolicyMode_TP_MODE_UNKNOWN
	}
	mode, err := policyconf.PolicyMode(c.tracingpolicy)
	if err != nil {
		return tetragon.TracingPolicyMode_TP_MODE_UNKNOWN
	}

	switch mode {
	case policyconf.EnforceMode:
		return tetragon.TracingPolicyMode_TP_MODE_ENFORCE
	case policyconf.MonitorMode:
		return tetragon.TracingPolicyMode_TP_MODE_MONITOR
	}

	return tetragon.TracingPolicyMode_TP_MODE_UNKNOWN
}

func policyconfMode(mode tetragon.TracingPolicyMode) (policyconf.Mode, error) {
	switch mode {
	case tetragon.TracingPolicyMode_TP_MODE_ENFORCE:
		return policyconf.EnforceMode, nil
	case tetragon.TracingPolicyMode_TP_MODE_MONITOR:
		return policyconf.MonitorMode, nil
	}

	return policyconf.InvalidMode, fmt.Errorf("unexpected mode: %v", mode)
}

func (c *collection) setMode(mode tetragon.TracingPolicyMode) error {
	if c.tracingpolicy == nil {
		return errors.New("unexpected error: setMode called in a collection that is not a tracing policy")
	}

	m, err := policyconfMode(mode)
	if err != nil {
		return err
	}

	return policyconf.SetPolicyMode(c.tracingpolicy, m)
}

// load will attempt to load a collection of sensors. If loading one of the sensors fails, it
// will attempt to unload the already loaded sensors.
func (c *collection) load(bpfDir string) error {

	var err error
	for _, sensor := range c.sensors {
		if sensor.IsLoaded() {
			// NB: For now, we don't treat a sensor already loaded as an error
			// because that would complicate things.
			continue
		}
		if err = sensor.Load(bpfDir); err != nil {
			err = fmt.Errorf("sensor %s from collection %s failed to load: %s", sensor.GetName(), c.name, err)
			break
		}
	}

	// if there was an error, try to unload all the sensors
	if err != nil {
		// NB: we could try to unload sensors going back from the one that failed, but since
		// unload() checks s.IsLoaded, is easier to just to use unload().
		if unloadErr := c.unload(true); unloadErr != nil {
			err = multierr.Append(err, fmt.Errorf("unloading after loading failure failed: %w", unloadErr))
		}
	}

	return err
}

// unload will attempt to unload all the sensors in a collection
func (c *collection) unload(unpin bool) error {
	var err error
	for _, s := range c.sensors {
		if !s.IsLoaded() {
			continue
		}
		unloadErr := s.Unload(unpin)
		err = multierr.Append(err, unloadErr)
	}

	if err != nil {
		return fmt.Errorf("failed to unload all sensors from collection %s: %w", c.name, err)
	}
	return nil
}

// destroy will attempt to destroy all the sensors in a collection
func (c *collection) destroy(unpin bool) {
	for _, s := range c.sensors {
		s.Destroy(unpin)
	}
}
