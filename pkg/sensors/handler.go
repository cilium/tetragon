// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package sensors

import (
	"fmt"

	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/tetragon/api/v1/tetragon"
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
		// NB: we are using policy ids for filtering, so we start with
		// the first valid id. This is because value 0 is reserved to
		// indicate that there is no filtering in the bpf side.
		// FirstValidFilterPolicyID is 1, but this might change if we
		// introduce more special values in the future.
		nextPolicyID: policyfilter.FirstValidFilterPolicyID,
	}, nil
}

func (h *handler) allocPolicyID() uint64 {
	ret := h.nextPolicyID
	h.nextPolicyID++
	return ret
}

// revive:disable:exported
func SensorsFromPolicy(tp tracingpolicy.TracingPolicy, filterID policyfilter.PolicyID) ([]*Sensor, error) {
	return sensorsFromPolicyHandlers(tp, filterID)
}

// revive:enable:exported

// updatePolicyFilter will update the policyfilter state so that filtering for
// i) namespaced policies and ii) pod label filters happens.
//
// It returns:
//
//	policyfilter.NoFilterID, nil if no filtering is needed
//	policyfilter.PolicyID(tpID), nil if filtering is needed and policyfilter has been successfully set up
//	_, err if an error occurred
func (h *handler) updatePolicyFilter(tp tracingpolicy.TracingPolicy, tpID uint64) (policyfilter.PolicyID, error) {
	var namespace string
	if tpNs, ok := tp.(tracingpolicy.TracingPolicyNamespaced); ok {
		namespace = tpNs.TpNamespace()
	}

	var selector *slimv1.LabelSelector
	if ps := tp.TpSpec().PodSelector; ps != nil {
		if len(ps.MatchLabels)+len(ps.MatchExpressions) > 0 {
			selector = ps
		}
	}

	// we do not call AddPolicy unless filtering is actually needed. This
	// means that if policyfilter is disabled
	// (option.Config.EnablePolicyFilter is false) then loading the policy
	// will only fail if filtering is required.
	if namespace == "" && selector == nil {
		return policyfilter.NoFilterID, nil
	}

	filterID := policyfilter.PolicyID(tpID)
	if err := h.pfState.AddPolicy(filterID, namespace, selector); err != nil {
		return policyfilter.NoFilterID, err
	}
	return filterID, nil
}

func (h *handler) addTracingPolicy(op *tracingPolicyAdd) error {
	if _, exists := h.collections[op.name]; exists {
		return fmt.Errorf("failed to add tracing policy %s, a sensor collection with the name already exists", op.name)
	}
	tpID := h.allocPolicyID()

	// update policy filter state before loading the sensors of the policy.
	//
	// The filterID is set to a non-zero value only if we need to apply
	// filtering, so the policy handlers will receive a valid filter value
	// only if we want to apply filtering and NoFilterID otherwise. This
	// allows us to have sensors that do not support policyfilter continue
	// to work if no filtering is needed. A sensor that does not support
	// policyfilter should return an error on PolicyHandler if a filter id
	// other than filterID is passed.
	filterID, err := h.updatePolicyFilter(op.tp, tpID)
	if err != nil {
		return err
	}

	sensors, err := sensorsFromPolicyHandlers(op.tp, filterID)
	if err != nil {
		return err
	}

	col := collection{
		sensors:         sensors,
		name:            op.name,
		tracingpolicy:   op.tp,
		tracingpolicyID: uint64(tpID),
	}
	if err := col.load(h.bpfDir, h.mapDir, h.ciliumDir, nil); err != nil {
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
	return col.load(h.bpfDir, h.mapDir, h.ciliumDir, &LoadArg{STTManagerHandle: op.sttManagerHandle})
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
