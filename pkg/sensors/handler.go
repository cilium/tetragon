// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package sensors

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/bpf"
	gt "github.com/cilium/tetragon/pkg/generictypes"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/selectors"
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
	namespace, podSelector, containerSelector := getNamespaceAndSelectors(tp)

	// we do not call AddGenericPolicy unless filtering is actually needed. This
	// means that if policyfilter is disabled
	// (option.Config.EnablePolicyFilter is false) then loading the policy
	// will only fail if filtering is required.
	if namespace == "" && podSelector == nil && containerSelector == nil {
		// if this is a policy template we will return here because we validated the policy ahead of time
		return policyfilter.NoFilterID, nil
	}

	filterID := policyfilter.PolicyID(tpID)
	if err := h.pfState.AddGenericPolicy(filterID, namespace, podSelector, containerSelector); err != nil {
		return policyfilter.NoFilterID, err
	}
	return filterID, nil
}

func (h *handler) addTracingPolicyBinding(currCol *collection) error {
	var err error
	defer func() {
		if err != nil {
			currCol.err = err
			currCol.state = LoadErrorState
		} else {
			currCol.state = EnabledState
		}
	}()

	namespace, podSelector, containerSelector := getNamespaceAndSelectors(currCol.tracingpolicy)
	if namespace == "" && podSelector == nil && containerSelector == nil {
		return errors.New("we should have at least a pod or container selector for binding policies")
	}

	spec := currCol.tracingpolicy.TpSpec()

	// Get the referenced policy name
	refPolicyName := getRefPolicyFromOptions(spec.Options)
	// default format is name only
	namespaceRefPol := "" // if not namespaced the namespace should be ""
	nameRefPol := refPolicyName
	parts := strings.Split(refPolicyName, "/")
	if len(parts) == 2 {
		// if namespaced this is in namespace/name format
		namespaceRefPol = parts[0]
		nameRefPol = parts[1]
	}

	ck := collectionKey{nameRefPol, namespaceRefPol}

	refCol, exists := h.collections.c[ck]
	if !exists {
		return fmt.Errorf("referenced policy %s does not exist", ck)
	}

	// todo: today we don't support enable/disable of binding policies
	if refCol.state != EnabledState {
		return fmt.Errorf("referenced policy %s is not enabled", ck)
	}

	if refCol.templateState == nil {
		return fmt.Errorf("referenced policy %s does not have template state", ck)
	}

	// Get values from the policy
	// comma separated list of values
	valuesList := getValuesFromOptions(spec.Options)
	values := strings.Split(valuesList, ",")

	// Create the workload map before populating the cgroup->policy map
	subMaps, err := selectors.ConvertValuesToMaps(values, refCol.templateState.ArgType)
	if err != nil {
		return fmt.Errorf("failed to convert values to maps: %w", err)
	}

	policyID := policyfilter.PolicyID(currCol.tracingpolicyID)
	stringMaps := refCol.templateState.PolicyStringMaps
	preKernelVersion5_9 := !kernels.MinKernelVersion("5.9")
	preKernelVersion5_11 := !kernels.MinKernelVersion("5.11")

	for i := range subMaps {
		// if the subMap is empty we skip it
		if len(subMaps[i]) == 0 {
			continue
		}

		mapKeySize := selectors.StringMapsSizes[i]
		if i == 7 && preKernelVersion5_11 {
			mapKeySize = selectors.StringMapSize7a
		}

		name := fmt.Sprintf("p_%d_str_map_%d", policyID, i)
		innerSpec := &ebpf.MapSpec{
			Name:       name,
			Type:       ebpf.Hash,
			KeySize:    uint32(mapKeySize),
			ValueSize:  uint32(1),
			MaxEntries: uint32(len(subMaps[i])),
		}

		if preKernelVersion5_9 {
			innerSpec.Flags = uint32(bpf.BPF_F_NO_PREALLOC)
			innerSpec.MaxEntries = uint32(200)
		}

		inner, err := ebpf.NewMap(innerSpec)
		if err != nil {
			return fmt.Errorf("failed to create inner_map: %w", err)
		}

		// update values
		// todo: ideally we should rollback if any of these fail
		one := uint8(1)
		for rawVal := range subMaps[i] {
			val := rawVal[:mapKeySize]
			err := inner.Update(val, one, 0)
			if err != nil {
				return fmt.Errorf("failed to insert value into %s: %w", name, err)
			}
		}

		err = stringMaps[i].Update(policyID, uint32(inner.FD()), ebpf.UpdateNoExist)
		if err != nil && errors.Is(err, ebpf.ErrKeyExist) {
			logger.GetLogger().Warn("inner policy map entry already exists, retrying update", "map", name, "policyID", policyID)
			err = stringMaps[i].Update(policyID, uint32(inner.FD()), 0)
		}
		inner.Close()
		if err != nil {
			return fmt.Errorf("failed to insert inner policy (id=%d) map: %w", policyID, err)
		}
		logger.GetLogger().Info("handler: add new inner map inside policy str", "name", name)
	}

	err = h.pfState.AddTracingPolicyBinding(policyID, policyfilter.PolicyID(refCol.tracingpolicyID), namespace, podSelector, containerSelector)
	if err != nil {
		// cleanup of the maps
		for i := range subMaps {
			err = stringMaps[i].Delete(policyID)
			if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				logger.GetLogger().Warn("map entry doesn't exist, retrying update", "map", stringMaps[i].String(), "policyID", policyID)
			}
		}
		return fmt.Errorf("failed to add for-each-cgroup-values policy to policyfilter: %w", err)
	}

	currCol.refCollection = refCol
	logger.GetLogger().Info("handler: add tracing policy binding to template", "name", currCol.name, "policy_id", currCol.tracingpolicyID, "template_id", refCol.tracingpolicyID)
	return nil
}

func (h *handler) addTracingPolicyTemplate(col *collection) error {
	if len(col.sensors) == 0 {
		return errors.New("template policy requires at least one sensor")
	}

	// all sensors should have the maps we need since are shared across sensors, so we use the first one for simplicity
	sensor := col.sensors[0]

	// Get the cgroup to policy map handle
	cgroupMapHandle := sensor.GetCgroupToPolicyMapHandle()
	if cgroupMapHandle == nil {
		return errors.New("template policy requires a cgroup to policy map")
	}

	// Get the policy string maps
	policyStringMaps := sensor.GetPolicyStringMapHandles()
	if len(policyStringMaps) == 0 {
		return errors.New("template policy requires policy string maps")
	}

	// We will need the type when populating the maps for the template
	argTypeString := getArgTypeFromOptions(col.tracingpolicy.TpSpec().Options)
	if argTypeString == "" {
		return errors.New("template policy requires arg type option")
	}
	argType := gt.GenericTypeFromString(argTypeString)
	if argType == gt.GenericInvalidType {
		return fmt.Errorf("invalid arg type string: %s", argTypeString)
	}

	// Populate the state of the collection
	col.templateState = &TemplateState{
		ArgType:          uint32(argType),
		PolicyStringMaps: policyStringMaps,
	}

	// we can use the tracingpolicyID as identifier since it is unique in the policyFilter state
	if err := h.pfState.AddTracingPolicyTemplate(policyfilter.PolicyID(col.tracingpolicyID), cgroupMapHandle); err != nil {
		return err
	}

	logger.GetLogger().Info("handler: add tracing policy template", "name", col.name, "namespace", "template_id", col.tracingpolicyID)
	return nil
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

	if isTracingPolicyBinding(op.tp.TpSpec().Options) {
		return h.addTracingPolicyBinding(&col)
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

	if IsTracingPolicyTemplate(op.tp.TpSpec().Options) {
		if err = h.addTracingPolicyTemplate(&col); err != nil {
			col.err = err
			col.state = LoadErrorState
			return err
		}
	}

	col.state = EnabledState
	return nil
}

func (h *handler) deleteTracingPolicyBinding(col *collection) error {
	if col.refCollection == nil {
		return errors.New("deleteTracingPolicyBinding called on a non-binding policy")
	}

	logger.GetLogger().Info("handler: delete tracing policy binding for template", "name", col.name, "policy_id", col.tracingpolicyID, "template_id", col.refCollection.tracingpolicyID)

	// first remove the mapping cgroup -> policy
	if err := h.pfState.DeleteTracingPolicyBinding(policyfilter.PolicyID(col.tracingpolicyID)); err != nil {
		return err
	}

	// We need to remove the entries in the string maps
	maps := col.refCollection.templateState.PolicyStringMaps
	for i := range maps {
		logger.GetLogger().Info("handler: delete entry in the policy string map", "map_name", maps[i].String(), "map_id", i, "policy_id", col.tracingpolicyID)
		err := maps[i].Delete(policyfilter.PolicyID(col.tracingpolicyID))
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			logger.GetLogger().Warn("cannot delete map entry", "map", maps[i].String(), "policyID", col.tracingpolicyID, "error", err)
		}
	}
	return nil
}

func (h *handler) deleteTracingPolicyTemplate(col *collection) error {
	logger.GetLogger().Info("handler: delete tracing policy template", "name", col.name, "id", col.tracingpolicyID)

	// first we need to disable the cgroup -> policy population from the pods in the policyfilter state
	if err := h.pfState.DeleteTracingPolicyTemplate(policyfilter.PolicyID(col.tracingpolicyID)); err != nil {
		return err
	}
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

	if col.isCollectionBinding() {
		if err := h.deleteTracingPolicyBinding(col); err != nil {
			h.collections.mu.Unlock()
			return fmt.Errorf("failed to delete tracing policy binding %s: %w", op.ck, err)
		}
	}

	if col.isCollectionTemplate() {
		if err := h.deleteTracingPolicyTemplate(col); err != nil {
			h.collections.mu.Unlock()
			return fmt.Errorf("failed to delete tracing policy binding %s: %w", op.ck, err)
		}

		// remove all the collections associated with this template
		for k, c := range collections {
			if !c.isCollectionBinding() {
				continue
			}
			if c.refCollection.tracingpolicyID != col.tracingpolicyID {
				continue
			}
			delete(collections, k)
		}
	}

	delete(collections, op.ck)
	// we have removed the collection, so unlock the map so that the lister can quickly view
	// that the collection is gone
	h.collections.mu.Unlock()

	// this has no effect for tracing bindings
	col.destroy(true)

	// this has no effect for tracing bindings and templates
	filterID := policyfilter.PolicyID(col.policyfilterID)
	err := h.pfState.DeleteGenericPolicy(filterID)
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
			Stats:    col.stats(),
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
