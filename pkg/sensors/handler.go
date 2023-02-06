// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package sensors

import (
	"fmt"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

type handler struct {
	// map of sensor collections: name -> collection
	collections               map[string]collection
	bpfDir, mapDir, ciliumDir string

	nextPolicyID uint64
	pfState      policyfilter.State
}

func newHandler(bpfDir, mapDir, ciliumDir string) (*handler, error) {
	pfState, err := policyfilter.GetState()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize policy filter state: %w", err)
	}

	return &handler{
		collections: map[string]collection{},
		bpfDir:      bpfDir,
		mapDir:      mapDir,
		ciliumDir:   ciliumDir,
		pfState:     pfState,
		// NB: policy ids start with 1, so that they can be used for filtering. In policy
		// filtering code, a policy id of 0 means no filtering.
		nextPolicyID: 1,
	}, nil
}

func (h *handler) allocPolicyID() uint64 {
	ret := h.nextPolicyID
	h.nextPolicyID++
	return ret
}

// revive:disable:exported
func SensorsFromPolicy(tp tracingpolicy.TracingPolicy, filterID policyfilter.PolicyID) ([]*Sensor, error) {
	sensors, err := sensorsFromSpecHandlers(tp)
	if err != nil {
		return nil, err
	}
	policySensors, err := sensorsFromPolicyHandlers(tp, filterID)
	if err != nil {
		return nil, err
	}
	sensors = append(sensors, policySensors...)
	return sensors, nil
}

// revive:enable:exported

func (h *handler) addTracingPolicy(op *tracingPolicyAdd) error {
	if _, exists := h.collections[op.name]; exists {
		return fmt.Errorf("failed to add tracing policy %s, a sensor collection with the name already exists", op.name)
	}
	tpID := h.allocPolicyID()
	filterID := policyfilter.PolicyID(0)

	// This is a namespaced policy, so update policy filter state before loading the sensors
	// NB: the filterID is set to a non-zero value only if we have a namespaced policy and need
	// to apply filtering.
	if tpNs, ok := op.tp.(tracingpolicy.TracingPolicyNamespaced); ok {
		filterID = policyfilter.PolicyID(tpID)
		if err := h.pfState.AddPolicy(filterID, tpNs.TpNamespace()); err != nil {
			return err
		}
	}

	sensors, err := sensorsFromSpecHandlers(op.tp)
	if err != nil {
		return err
	}
	policySensors, err := sensorsFromPolicyHandlers(op.tp, filterID)
	if err != nil {
		return err
	}
	sensors = append(sensors, policySensors...)

	col := collection{
		sensors:         sensors,
		name:            op.name,
		tracingpolicy:   op.tp,
		tracingpolicyID: uint64(tpID),
	}
	if err := col.load(op.ctx, h.bpfDir, h.mapDir, h.ciliumDir, nil); err != nil {
		return err
	}

	// NB: in some cases it might make sense to keep the policy registered if there was an
	// error. For now, however, we only keep it if it was successfully loaded
	h.collections[op.name] = col
	return nil
}

func (h *handler) delTracingPolicy(op *tracingPolicyDel) error {
	col, exists := h.collections[op.name]
	if !exists {
		return fmt.Errorf("tracing policy %s does not exist", op.name)
	}
	err := col.unload(nil)
	delete(h.collections, op.name)
	return err
}

func (h *handler) listTracingPolicies(op *tracingPolicyList) error {
	ret := tetragon.ListTracingPoliciesResponse{}
	for name, col := range h.collections {
		if col.tracingpolicy == nil {
			continue
		}

		pol := tetragon.TracingPolicyStatus{
			Id:   col.tracingpolicyID,
			Name: name,
			Info: col.tracingpolicy.TpInfo(),
		}

		pol.Namespace = ""
		if tpNs, ok := col.tracingpolicy.(tracingpolicy.TracingPolicyNamespaced); ok {
			pol.Namespace = tpNs.TpNamespace()
		}

		for _, sens := range col.sensors {
			pol.Sensors = append(pol.Sensors, sens.Name)
		}

		ret.Policies = append(ret.Policies, &pol)

	}
	op.result = &ret
	return nil
}

func (h *handler) addSensor(op *sensorAdd) error {
	if _, exists := h.collections[op.name]; exists {
		return fmt.Errorf("sensor %s already exists", op.name)
	}
	h.collections[op.name] = collection{
		sensors: []*Sensor{op.sensor},
		name:    op.name,
	}
	return nil
}

func (h *handler) removeSensor(op *sensorRemove) error {
	col, exists := h.collections[op.name]
	if !exists {
		return fmt.Errorf("sensor %s does not exist", op.name)
	}
	err := col.unload(nil)
	delete(h.collections, op.name)
	return err
}

func (h *handler) enableSensor(op *sensorEnable) error {
	col, exists := h.collections[op.name]
	if !exists {
		return fmt.Errorf("sensor %s does not exist", op.name)
	}

	// NB: LoadArg was passed for a previous implementation of a sensor.
	// The idea is that sensors can get a handle to the stt manager when
	// they are loaded which they can use to attach stt information to
	// events. Need to revsit this, and until we do we keep LoadArg.
	return col.load(op.ctx, h.bpfDir, h.mapDir, h.ciliumDir, &LoadArg{STTManagerHandle: op.sttManagerHandle})
}

func (h *handler) disableSensor(op *sensorDisable) error {
	col, exists := h.collections[op.name]
	if !exists {
		return fmt.Errorf("sensor %s does not exist", op.name)
	}

	// NB: see LoadArg for sensorEnable
	return col.unload(&UnloadArg{STTManagerHandle: op.sttManagerHandle})
}

func (h *handler) listSensors(op *sensorList) error {
	ret := make([]SensorStatus, 0)
	for _, col := range h.collections {
		colInfo := col.info()
		for _, s := range col.sensors {
			ret = append(ret, SensorStatus{
				Name:       s.Name,
				Enabled:    s.Loaded,
				Collection: colInfo,
			})
		}
	}
	op.result = &ret
	return nil
}

func (h *handler) configSet(op *sensorConfigSet) error {
	col, exists := h.collections[op.name]
	if !exists {
		return fmt.Errorf("sensor %s does not exist", op.name)
	}
	// NB: sensorConfigSet was used before tracing policies were
	// introduced. The idea was that it could be used to provide
	// sensor-specifc configuration values. We can either modify the
	// call to specify a sensor within a collection, or completely
	// remove it. TBD.
	if len(col.sensors) != 1 {
		return fmt.Errorf("configuration only supported for collections of one sensor, but %s has %d sensors", op.name, len(col.sensors))
	}
	s := col.sensors[0]
	if s.Ops == nil {
		return fmt.Errorf("sensor %s does not support configuration", op.name)
	}
	if err := s.Ops.SetConfig(op.key, op.val); err != nil {
		return fmt.Errorf("sensor %s SetConfig failed: %w", op.name, err)
	}

	return nil
}

func (h *handler) configGet(op *sensorConfigGet) error {
	col, exists := h.collections[op.name]
	if !exists {
		return fmt.Errorf("sensor %s does not exist", op.name)
	}
	// NB: see sensorConfigSet
	if len(col.sensors) != 1 {
		return fmt.Errorf("configuration only supported for collections of one sensor, but %s has %d sensors", op.name, len(col.sensors))
	}
	s := col.sensors[0]
	if s.Ops == nil {
		return fmt.Errorf("sensor %s does not support configuration", op.name)
	}

	var err error
	op.val, err = s.Ops.GetConfig(op.key)
	if err != nil {
		return fmt.Errorf("sensor %s GetConfig failed: %s", op.name, err)
	}

	return nil
}
func sensorsFromSpecHandlers(tp tracingpolicy.TracingPolicy) ([]*Sensor, error) {
	var sensors []*Sensor
	_, isNamespaced := tp.(tracingpolicy.TracingPolicyNamespaced)
	spec := tp.TpSpec()
	log := logger.GetLogger().WithField("policy-name", tp.TpName())

	for n, s := range registeredSpecHandlers {
		if isNamespaced {
			// NB: requires using policyHandler
			log.WithField("sensor-name", n).Warn("sensor will be ignored because it cannot handle namespaced tracing policy")
		}
		var sensor *Sensor
		sensor, err := s.SpecHandler(spec)
		if err != nil {
			return nil, fmt.Errorf("spec handler %s failed: %w", n, err)
		}
		if sensor == nil {
			continue
		}
		sensors = append(sensors, sensor)
	}
	return sensors, nil
}

func sensorsFromPolicyHandlers(tp tracingpolicy.TracingPolicy, filterID policyfilter.PolicyID) ([]*Sensor, error) {
	var sensors []*Sensor
	for n, s := range registeredPolicyHandlers {
		var sensor *Sensor
		sensor, err := s.PolicyHandler(tp, filterID)
		if err != nil {
			return nil, fmt.Errorf("policy handler %s failed: %w", n, err)
		}
		if sensor == nil {
			continue
		}
		sensors = append(sensors, sensor)
	}

	return sensors, nil
}
