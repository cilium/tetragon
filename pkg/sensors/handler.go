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
	// map of sensor collections: name, namespace -> collection
	collections map[collectionKey]*collection
	bpfDir      string

	nextPolicyID uint64
	pfState      policyfilter.State
}

func newHandler(
	pfState policyfilter.State,
	bpfDir string) (*handler, error) {
	return &handler{
		collections: map[collectionKey]*collection{},
		bpfDir:      bpfDir,
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

	var podSelector *slimv1.LabelSelector
	if ps := tp.TpSpec().PodSelector; ps != nil {
		if len(ps.MatchLabels)+len(ps.MatchExpressions) > 0 {
			podSelector = ps
		}
	}

	var containerSelector *slimv1.LabelSelector
	if ps := tp.TpSpec().ContainerSelector; ps != nil {
		if len(ps.MatchLabels)+len(ps.MatchExpressions) > 0 {
			containerSelector = ps
		}
	}

	// we do not call AddPolicy unless filtering is actually needed. This
	// means that if policyfilter is disabled
	// (option.Config.EnablePolicyFilter is false) then loading the policy
	// will only fail if filtering is required.
	if namespace == "" && podSelector == nil && containerSelector == nil {
		return policyfilter.NoFilterID, nil
	}

	filterID := policyfilter.PolicyID(tpID)
	if err := h.pfState.AddPolicy(filterID, namespace, podSelector, containerSelector); err != nil {
		return policyfilter.NoFilterID, err
	}
	return filterID, nil
}

func (h *handler) addTracingPolicy(op *tracingPolicyAdd) error {
	// allow overriding existing policy collection that resulted in an error
	// during the loading state
	if col, exists := h.collections[op.ck]; exists && col.state != LoadErrorState {
		return fmt.Errorf("failed to add tracing policy %s, a sensor collection with the key already exists", op.ck)
	}
	tpID := h.allocPolicyID()

	col := collection{
		name:            op.ck.name,
		tracingpolicy:   op.tp,
		tracingpolicyID: uint64(tpID),
	}

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
		col.err = err
		col.state = LoadErrorState
		h.collections[op.ck] = &col
		return err
	}
	col.policyfilterID = uint64(filterID)

	sensors, err := sensorsFromPolicyHandlers(op.tp, filterID)
	if err != nil {
		col.err = err
		col.state = LoadErrorState
		h.collections[op.ck] = &col
		return err
	}
	col.sensors = sensors

	if err := col.load(h.bpfDir); err != nil {
		col.err = err
		col.state = LoadErrorState
		h.collections[op.ck] = &col
		return err
	}
	col.state = EnabledState

	h.collections[op.ck] = &col
	return nil
}

func (h *handler) deleteTracingPolicy(op *tracingPolicyDelete) error {
	col, exists := h.collections[op.ck]
	if !exists {
		return fmt.Errorf("tracing policy %s does not exist", op.ck)
	}
	defer delete(h.collections, op.ck)

	col.destroy()

	filterID := policyfilter.PolicyID(col.policyfilterID)
	err := h.pfState.DelPolicy(filterID)
	if err != nil {
		return fmt.Errorf("failed to remove from policyfilter: %w", err)
	}

	return nil
}

func (h *handler) listTracingPolicies(op *tracingPolicyList) error {
	ret := tetragon.ListTracingPoliciesResponse{}
	for ck, col := range h.collections {
		if col.tracingpolicy == nil {
			continue
		}

		pol := tetragon.TracingPolicyStatus{
			Id:       col.tracingpolicyID,
			Name:     ck.name,
			Enabled:  col.state == EnabledState,
			FilterId: col.policyfilterID,
			State:    col.state.ToTetragonState(),
		}

		if col.err != nil {
			pol.Error = col.err.Error()
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

func (h *handler) disableTracingPolicy(op *tracingPolicyDisable) error {
	col, exists := h.collections[op.ck]
	if !exists {
		return fmt.Errorf("tracing policy %s does not exist", op.ck)
	}

	if col.state == DisabledState {
		return fmt.Errorf("tracing policy %s is already disabled", op.ck)
	}

	err := col.unload()
	if err != nil {
		// for now, the only way col.unload() can return an error is if the
		// collection is not currently loaded, which should be impossible
		col.err = fmt.Errorf("failed to unload tracing policy %q: %w", col.name, err)
		col.state = ErrorState
		h.collections[op.ck] = col
		return col.err
	}

	col.state = DisabledState
	h.collections[op.ck] = col
	return nil
}

func (h *handler) enableTracingPolicy(op *tracingPolicyEnable) error {
	col, exists := h.collections[op.ck]
	if !exists {
		return fmt.Errorf("tracing policy %s does not exist", op.ck)
	}

	if col.state == EnabledState {
		return fmt.Errorf("tracing policy %s is already enabled", op.ck)
	}

	if err := col.load(h.bpfDir); err != nil {
		col.state = LoadErrorState
		col.err = fmt.Errorf("failed to load tracing policy %q: %w", col.name, err)
		h.collections[op.ck] = col
		return col.err
	}

	col.state = EnabledState
	h.collections[op.ck] = col
	return nil
}

func (h *handler) addSensor(op *sensorAdd) error {
	// Treat sensors as cluster-wide operations
	ck := collectionKey{op.name, ""}
	if _, exists := h.collections[ck]; exists {
		return fmt.Errorf("sensor %s already exists", ck)
	}
	h.collections[ck] = &collection{
		sensors: []*Sensor{op.sensor},
		name:    op.name,
	}
	return nil
}

func removeAllSensors(h *handler) {
	for ck, col := range h.collections {
		col.destroy()
		delete(h.collections, ck)
	}
}

func (h *handler) removeSensor(op *sensorRemove) error {
	if op.all {
		if op.name != "" {
			return fmt.Errorf("removeSensor called with all flag and sensor name %s",
				op.name)
		}
		removeAllSensors(h)
		return nil
	}
	// Treat sensors as cluster-wide operations
	ck := collectionKey{op.name, ""}
	col, exists := h.collections[ck]
	if !exists {
		return fmt.Errorf("sensor %s does not exist", ck)
	}

	col.destroy()
	delete(h.collections, ck)
	return nil
}

func (h *handler) enableSensor(op *sensorEnable) error {
	// Treat sensors as cluster-wide operations
	ck := collectionKey{op.name, ""}
	col, exists := h.collections[ck]
	if !exists {
		return fmt.Errorf("sensor %s does not exist", ck)
	}

	return col.load(h.bpfDir)
}

func (h *handler) disableSensor(op *sensorDisable) error {
	// Treat sensors as cluster-wide operations
	ck := collectionKey{op.name, ""}
	col, exists := h.collections[ck]
	if !exists {
		return fmt.Errorf("sensor %s does not exist", ck)
	}

	return col.unload()
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

func sensorsFromPolicyHandlers(tp tracingpolicy.TracingPolicy, filterID policyfilter.PolicyID) ([]*Sensor, error) {
	var sensors []*Sensor
	for n, s := range registeredPolicyHandlers {
		var sensor *Sensor
		sensor, err := s.PolicyHandler(tp, filterID)
		if err != nil {
			return nil, fmt.Errorf("policy handler '%s' failed loading policy '%s': %w", n, tp.TpName(), err)
		}
		if sensor == nil {
			continue
		}
		sensors = append(sensors, sensor)
	}

	return sensors, nil
}
