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

	selNamesMapName, ok := pinMap["sel_names_map"]
	if !ok {
		return fmt.Errorf("cannot find pinned sel_names_map")
	}
	selNamesMapName = filepath.Join(bpf.MapPrefixPath(), selNamesMapName)
	selNamesMap, err := ebpf.LoadPinnedMap(selNamesMapName, nil)
	if err != nil {
		return fmt.Errorf("failed to open sel_names_map map %s: %w", selNamesMapName, err)
	}
	defer selNamesMap.Close()

	if err := populateBinariesMaps(ks, pinPathPrefix, selNamesMap); err != nil {
		return fmt.Errorf("failed to populate sel_names_map: %w", err)
	}

	return nil
}

func selectorsMaploads(ks *selectors.KernelSelectorState, pinPathPrefix string, index uint32) []*program.MapLoad {
	selBuff := ks.Buffer()
	return []*program.MapLoad{
		{
			Index: index,
			Name:  "filter_map",
			Load: func(m *ebpf.Map, index uint32) error {
				return m.Update(index, selBuff[:], ebpf.UpdateAny)
			},
		}, {
			Index: 0,
			Name:  "argfilter_maps",
			Load: func(outerMap *ebpf.Map, index uint32) error {
				return populateArgFilterMaps(ks, pinPathPrefix, outerMap)
			},
		}, {
			Index: 0,
			Name:  "sel_names_map",
			Load: func(outerMap *ebpf.Map, index uint32) error {
				return populateBinariesMaps(ks, pinPathPrefix, outerMap)
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

func populateBinariesMaps(
	ks *selectors.KernelSelectorState,
	pinPathPrefix string,
	outerMap *ebpf.Map,
) error {
	for innerID, sel := range ks.GetBinSelNamesMap() {
		innerName := fmt.Sprintf("sel_names_map_%d", innerID)
		innerSpec := &ebpf.MapSpec{
			Name:       innerName,
			Type:       ebpf.Hash,
			KeySize:    4, // uint32
			ValueSize:  4, // uint32
			MaxEntries: 256,
		}
		innerMap, err := ebpf.NewMapWithOptions(innerSpec, ebpf.MapOptions{
			PinPath: sensors.PathJoin(pinPathPrefix, innerName),
		})
		if err != nil {
			return fmt.Errorf("creating innerMap %s failed: %w", innerName, err)
		}
		defer innerMap.Close()

		// add a special entry (key == UINT32_MAX) that has as a value the operator (In or NotIn)
		if err := innerMap.Update(uint32(0xffffffff), ks.GetBinaryOp(innerID), ebpf.UpdateAny); err != nil {
			return err
		}

		for idx, val := range sel.GetBinSelNamesMap() {
			if err := innerMap.Update(idx, val, ebpf.UpdateAny); err != nil {
				return err
			}
		}

		if err := outerMap.Update(uint32(innerID), uint32(innerMap.FD()), 0); err != nil {
			return fmt.Errorf("failed to insert %s: %w", innerName, err)
		}
	}
	return nil
}
