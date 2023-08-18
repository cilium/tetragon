// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/selectors"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

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
			Name:  "addr4lpm_maps",
			Load: func(outerMap *ebpf.Map, index uint32) error {
				return populateAddr4FilterMaps(ks, pinPathPrefix, outerMap)
			},
		}, {
			Index: 0,
			Name:  "addr6lpm_maps",
			Load: func(outerMap *ebpf.Map, index uint32) error {
				return populateAddr6FilterMaps(ks, pinPathPrefix, outerMap)
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
	maxEntries := k.ValueMapsMaxEntries()
	for i, vm := range k.ValueMaps() {
		nrEntries := uint32(len(vm.Data))
		// Versions before 5.9 do not allow inner maps to have different sizes.
		// See: https://lore.kernel.org/bpf/20200828011800.1970018-1-kafai@fb.com/
		if !kernels.MinKernelVersion("5.9") {
			nrEntries = uint32(maxEntries)
		}
		err := populateArgFilterMap(pinPathPrefix, outerMap, uint32(i), vm.Data, nrEntries)
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
	maxEntries uint32,
) error {
	innerName := fmt.Sprintf("argfilter_map_%d", innerID)
	innerSpec := &ebpf.MapSpec{
		Name:       innerName,
		Type:       ebpf.Hash,
		KeySize:    8, // NB: hardcoded to 64 bits for now
		ValueSize:  uint32(1),
		MaxEntries: maxEntries,
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

func populateAddr4FilterMaps(
	k *selectors.KernelSelectorState,
	pinPathPrefix string,
	outerMap *ebpf.Map,
) error {
	maxEntries := k.Addr4MapsMaxEntries()
	for i, am := range k.Addr4Maps() {
		nrEntries := uint32(len(am))
		// Versions before 5.9 do not allow inner maps to have different sizes.
		// See: https://lore.kernel.org/bpf/20200828011800.1970018-1-kafai@fb.com/
		if !kernels.MinKernelVersion("5.9") {
			nrEntries = uint32(maxEntries)
		}
		err := populateAddr4FilterMap(pinPathPrefix, outerMap, uint32(i), am, nrEntries)
		if err != nil {
			return err
		}
	}
	return nil
}

func populateAddr4FilterMap(
	pinPathPrefix string,
	outerMap *ebpf.Map,
	innerID uint32,
	innerData map[selectors.KernelLpmTrie4]struct{},
	maxEntries uint32,
) error {
	innerName := fmt.Sprintf("addr4filter_map_%d", innerID)
	innerSpec := &ebpf.MapSpec{
		Name:       innerName,
		Type:       ebpf.LPMTrie,
		KeySize:    8, // NB: KernelLpmTrie4 consists of 32bit prefix and 32bit address
		ValueSize:  uint32(1),
		MaxEntries: maxEntries,
		Flags:      bpf.BPF_F_NO_PREALLOC,
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
		err := innerMap.Update(val, one, 0)
		if err != nil {
			return fmt.Errorf("failed to insert value into %s: %w", innerName, err)
		}
	}

	if err := outerMap.Update(uint32(innerID), uint32(innerMap.FD()), 0); err != nil {
		return fmt.Errorf("failed to insert %s: %w", innerName, err)
	}

	return nil
}

func populateAddr6FilterMaps(
	k *selectors.KernelSelectorState,
	pinPathPrefix string,
	outerMap *ebpf.Map,
) error {
	maxEntries := k.Addr6MapsMaxEntries()
	for i, am := range k.Addr6Maps() {
		nrEntries := uint32(len(am))
		// Versions before 5.9 do not allow inner maps to have different sizes.
		// See: https://lore.kernel.org/bpf/20200828011800.1970018-1-kafai@fb.com/
		if !kernels.MinKernelVersion("5.9") {
			nrEntries = uint32(maxEntries)
		}
		err := populateAddr6FilterMap(pinPathPrefix, outerMap, uint32(i), am, nrEntries)
		if err != nil {
			return err
		}
	}
	return nil
}

func populateAddr6FilterMap(
	pinPathPrefix string,
	outerMap *ebpf.Map,
	innerID uint32,
	innerData map[selectors.KernelLpmTrie6]struct{},
	maxEntries uint32,
) error {
	innerName := fmt.Sprintf("addr6filter_map_%d", innerID)
	innerSpec := &ebpf.MapSpec{
		Name:       innerName,
		Type:       ebpf.LPMTrie,
		KeySize:    20, // NB: KernelLpmTrie6 consists of 32bit prefix and 128bit address
		ValueSize:  uint32(1),
		MaxEntries: maxEntries,
		Flags:      bpf.BPF_F_NO_PREALLOC,
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
		err := innerMap.Update(val, one, 0)
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
