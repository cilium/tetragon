// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"fmt"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/selectors"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

// internal functions for dealing with selectors that are common for kprobes/tracepoints

// updateSelectors will update filter_map and argfilter_maps based on the provided kernel selectors
func updateSelectors(
	ks *selectors.KernelSelectorState,
	pinMap map[string]string,
	pinPathPrefix string,
) error {

	filterName, ok := pinMap["filter_map"]
	if !ok {
		return fmt.Errorf("cannot find pinned filter_map")
	}
	filterMapPath := filepath.Join(bpf.MapPrefixPath(), filterName)
	filterMap, err := ebpf.LoadPinnedMap(filterMapPath, nil)
	if err != nil {
		return fmt.Errorf("failed to open filter map: %w", err)
	}
	defer filterMap.Close()

	selBuff := ks.Buffer()
	if err := filterMap.Update(uint32(0), selBuff[:], ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to update filter data: %w", err)
	}

	argfilterMapsName, ok := pinMap["argfilter_maps"]
	if !ok {
		return fmt.Errorf("cannot find pinned argfilter_maps")
	}
	argfilterMapsName = filepath.Join(bpf.MapPrefixPath(), argfilterMapsName)
	argfilterMaps, err := ebpf.LoadPinnedMap(argfilterMapsName, nil)
	if err != nil {
		return fmt.Errorf("failed to open argfilter_map map %s: %w", argfilterMapsName, err)
	}
	defer argfilterMaps.Close()
	if err := populateArgFilterMaps(ks, pinPathPrefix, argfilterMaps); err != nil {
		return fmt.Errorf("failed to populate argfilter_maps: %w", err)
	}

	return nil
}

func selectorsMaploads(ks *selectors.KernelSelectorState, pinPathPrefix string) []*program.MapLoad {
	selBuff := ks.Buffer()
	return []*program.MapLoad{
		{
			Name: "filter_map",
			Load: func(m *ebpf.Map) error {
				return m.Update(uint32(0), selBuff[:], ebpf.UpdateAny)
			},
		}, {
			Name: "argfilter_maps",
			Load: func(outerMap *ebpf.Map) error {
				return populateArgFilterMaps(ks, pinPathPrefix, outerMap)
			},
		},
	}
}

func populateArgFilterMaps(
	k *selectors.KernelSelectorState,
	pinPathPrefix string,
	outerMap *ebpf.Map,
) error {
	for i, vm := range k.ValueMaps() {
		err := populateArgFilterMap(pinPathPrefix, outerMap, uint32(i), vm)
		if err != nil {
			return err
		}
	}
	return nil
}

func populateArgFilterMap(
	pinPathPrefix string,
	outerMap *ebpf.Map,
	innerID uint32,
	innerData map[[8]byte]struct{},
) error {
	innerName := fmt.Sprintf("argfilter_map_%d", innerID)
	innerSpec := &ebpf.MapSpec{
		Name:       innerName,
		Type:       ebpf.Hash,
		KeySize:    8, // NB: hardcoded to 64 bits for now
		ValueSize:  uint32(1),
		MaxEntries: uint32(len(innerData)),
	}
	innerMap, err := ebpf.NewMapWithOptions(innerSpec, ebpf.MapOptions{
		PinPath: sensors.PathJoin(pinPathPrefix, innerName),
	})
	if err != nil {
		return fmt.Errorf("creating innerMap %s failed: %w", innerName, err)
	}
	defer innerMap.Close()

	one := uint8(1)
	for val := range innerData {
		err := innerMap.Update(val[:], one, 0)
		if err != nil {
			return fmt.Errorf("failed to insert value into %s: %w", innerName, err)
		}
	}

	if err := outerMap.Update(uint32(innerID), uint32(innerMap.FD()), 0); err != nil {
		return fmt.Errorf("failed to insert %s: %w", innerName, err)
	}

	return nil
}
