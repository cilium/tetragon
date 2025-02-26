// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package sensors

import (
	"errors"
	"fmt"
	"sync"

	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

type handler struct {
	collections *collectionMap
	bpfDir      string

	nextPolicyID uint64
	pfState      policyfilter.State
	muLoad       sync.Mutex
}

func newHandler(
	pfState policyfilter.State,
	collections *collectionMap,
	bpfDir string) (*handler, error) {
	return &handler{
		collections: collections,
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

func (h *handler) load(col *collection) error {
	h.muLoad.Lock()
	defer h.muLoad.Unlock()
	return col.load(h.bpfDir)
}

func (h *handler) unload(col *collection, unpin bool) error {
	h.muLoad.Lock()
	defer h.muLoad.Unlock()
	return col.unload(unpin)
}

func (h *handler) allocPolicyID() uint64 {
	ret := h.nextPolicyID
	h.nextPolicyID++
	return ret
}

// revive:disable:exported
func SensorsFromPolicy(tp tracingpolicy.TracingPolicy, filterID policyfilter.PolicyID) ([]SensorIface, error) {
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
	h.collections.mu.Lock()
	defer h.collections.mu.Unlock()
	collections := h.collections.c
	// allow overriding existing policy collection that resulted in an error
	// during the loading state
	if col, exists := collections[op.ck]; exists && col.state != LoadErrorState {
		return fmt.Errorf("failed to add tracing policy %s, a sensor collection with the key already exists", op.ck)
	}
	tpID := h.allocPolicyID()

	col := collection{
		name:            op.ck.name,
		tracingpolicy:   op.tp,
		tracingpolicyID: uint64(tpID),
	}
	collections[op.ck] = &col

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
		return err
	}
	col.policyfilterID = uint64(filterID)

	sensors, err := sensorsFromPolicyHandlers(op.tp, filterID)
	if err != nil {
		col.err = err
		col.state = LoadErrorState
		return err
	}
	col.sensors = make([]SensorIface, 0, len(sensors))
	col.sensors = append(col.sensors, sensors...)
	col.state = LoadingState

	// unlock so that policyLister can access the collections (read-only) while we are loading.
	h.collections.mu.Unlock()
	err = h.load(&col)
	h.collections.mu.Lock()

	if err != nil {
		col.err = err
		col.state = LoadErrorState
		return err
	}
	col.state = EnabledState
	return nil
}

func (h *handler) deleteTracingPolicy(op *tracingPolicyDelete) error {
	h.collections.mu.Lock()
	collections := h.collections.c
	col, exists := collections[op.ck]
	if !exists {
		h.collections.mu.Unlock()
		return fmt.Errorf("tracing policy %s does not exist", op.ck)
	}
	delete(collections, op.ck)
	// we have removed the collection, so unlock the map so that the lister can quickly view
	// that the collection is gone
	h.collections.mu.Unlock()

	col.destroy(true)

	filterID := policyfilter.PolicyID(col.policyfilterID)
	err := h.pfState.DelPolicy(filterID)
	if err != nil {
		return fmt.Errorf("failed to remove from policyfilter: %w", err)
	}

	return nil
}

// should be called with h.collections.mu locked (for writing)
func (h *handler) doDisableTracingPolicy(col *collection) error {
	if col.state != EnabledState {
		return fmt.Errorf("tracing policy %s is not enabled", col.name)
	}

	col.state = UnloadingState
	// unlock so that policyLister can access the collections (read-only) while we are unloading.
	h.collections.mu.Unlock()
	err := h.unload(col, true)
	h.collections.mu.Lock()

	if err != nil {
		// for now, the only way col.unload() can return an error is if the
		// collection is not currently loaded, which should be impossible
		col.err = fmt.Errorf("failed to unload tracing policy %q: %w", col.name, err)
		col.state = ErrorState
		return col.err
	}

	col.state = DisabledState
	return nil
}

// should be called with h.collections.mu locked (for writing)
func (h *handler) doEnableTracingPolicy(col *collection) error {
	if col.state != DisabledState {
		return fmt.Errorf("tracing policy %s is not disabled", col.name)
	}

	col.state = LoadingState
	// unlock so that policyLister can access the collections (read-only) while we are loading.
	h.collections.mu.Unlock()
	err := h.load(col)
	h.collections.mu.Lock()

	if err != nil {
		col.state = LoadErrorState
		col.err = fmt.Errorf("failed to enable tracing policy %q: %w", col.name, err)
		return col.err
	}

	col.state = EnabledState
	return nil
}

func (h *handler) configureTracingPolicy(
	ck collectionKey,
	mode *tetragon.TracingPolicyMode,
	enable *bool,
) error {
	h.collections.mu.Lock()
	defer h.collections.mu.Unlock()
	collections := h.collections.c
	col, exists := collections[ck]
	if !exists {
		return fmt.Errorf("tracing policy %s does not exist", ck)
	}

	var err error

	// change mode of policy
	if mode != nil {
		err = errors.Join(err, col.setMode(*mode))
	}

	// enable or disable policy
	if enable != nil {
		if *enable {
			err = errors.Join(err, h.doEnableTracingPolicy(col))
		} else {
			err = errors.Join(err, h.doDisableTracingPolicy(col))
		}
	}

	return err
}

func (h *handler) addSensor(op *sensorAdd) error {
	h.collections.mu.Lock()
	defer h.collections.mu.Unlock()
	collections := h.collections.c
	// Treat sensors as cluster-wide operations
	ck := collectionKey{op.name, ""}
	if _, exists := collections[ck]; exists {
		return fmt.Errorf("sensor %s already exists", ck)
	}
	collections[ck] = &collection{
		sensors: []SensorIface{op.sensor},
		name:    op.name,
	}
	return nil
}

func removeAllSensors(h *handler, unpin bool) {
	h.collections.mu.Lock()
	defer h.collections.mu.Unlock()
	collections := h.collections.c
	for ck, col := range collections {
		col.destroy(unpin)
		delete(collections, ck)
	}
}

func (h *handler) removeSensor(op *sensorRemove) error {
	if op.all {
		if op.name != "" {
			return fmt.Errorf("removeSensor called with all flag and sensor name %s",
				op.name)
		}
		removeAllSensors(h, op.unpin)
		return nil
	}

	h.collections.mu.Lock()
	defer h.collections.mu.Unlock()
	collections := h.collections.c
	// Treat sensors as cluster-wide operations
	ck := collectionKey{op.name, ""}
	col, exists := collections[ck]
	if !exists {
		return fmt.Errorf("sensor %s does not exist", ck)
	}

	col.destroy(true)
	delete(collections, ck)
	return nil
}

func (h *handler) enableSensor(op *sensorEnable) error {
	h.collections.mu.Lock()
	collections := h.collections.c
	// Treat sensors as cluster-wide operations
	ck := collectionKey{op.name, ""}
	col, exists := collections[ck]
	h.collections.mu.Unlock()
	if !exists {
		return fmt.Errorf("sensor %s does not exist", ck)
	}
	return h.load(col)
}

func (h *handler) disableSensor(op *sensorDisable) error {
	h.collections.mu.Lock()
	collections := h.collections.c
	// Treat sensors as cluster-wide operations
	ck := collectionKey{op.name, ""}
	col, exists := collections[ck]
	h.collections.mu.Unlock()
	if !exists {
		return fmt.Errorf("sensor %s does not exist", ck)
	}
	return h.unload(col, true)
}

func (h *handler) listSensors(op *sensorList) error {
	h.collections.mu.RLock()
	defer h.collections.mu.RUnlock()
	collections := h.collections.c
	ret := make([]SensorStatus, 0)
	for _, col := range collections {
		colInfo := col.info()
		for _, s := range col.sensors {
			ret = append(ret, SensorStatus{
				Name:       s.GetName(),
				Enabled:    s.IsLoaded(),
				Collection: colInfo,
			})
		}
	}
	op.result = &ret
	return nil
}

func (h *handler) listOverheads() ([]ProgOverhead, error) {
	h.collections.mu.RLock()
	defer h.collections.mu.RUnlock()
	collections := h.collections.c

	overheads := []ProgOverhead{}

	for ck, col := range collections {
		for _, s := range col.sensors {
			ret, ok := s.Overhead()
			if !ok {
				continue
			}
			for _, ovh := range ret {
				ovh.Namespace = ck.namespace
				ovh.Policy = ck.name
				overheads = append(overheads, ovh)
			}
		}
	}

	return overheads, nil
}

func (h *handler) listPolicies() []*tetragon.TracingPolicyStatus {
	h.collections.mu.RLock()
	defer h.collections.mu.RUnlock()
	collections := h.collections.c

	ret := make([]*tetragon.TracingPolicyStatus, 0, len(collections))
	for ck, col := range collections {
		if col.tracingpolicy == nil {
			continue
		}

		pol := tetragon.TracingPolicyStatus{
			Id:       col.tracingpolicyID,
			Name:     ck.name,
			Enabled:  col.state == EnabledState,
			FilterId: col.policyfilterID,
			State:    col.state.ToTetragonState(),
			Mode:     col.mode(),
		}

		if col.err != nil {
			pol.Error = col.err.Error()
		}

		pol.Namespace = tracingpolicy.Namespace(col.tracingpolicy)

		for _, sens := range col.sensors {
			pol.Sensors = append(pol.Sensors, sens.GetName())
			pol.KernelMemoryBytes += uint64(sens.TotalMemlock())
		}

		ret = append(ret, &pol)
	}

	return ret
}

func sensorsFromPolicyHandlers(tp tracingpolicy.TracingPolicy, filterID policyfilter.PolicyID) ([]SensorIface, error) {
	var sensors []SensorIface
	for n, s := range registeredPolicyHandlers {
		sensor, err := s.PolicyHandler(tp, filterID)
		if err != nil {
			return nil, fmt.Errorf("policy handler '%s' failed loading policy '%s': %w", n, tp.TpName(), err)
		}
		if sensor == nil {
			continue
		}
		sensors = append(sensors, sensor)
	}

	sortSensors(sensors)
	return sensors, nil
}
