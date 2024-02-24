// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/mbset"
	"github.com/cilium/tetragon/pkg/selectors"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

func selectorsMaploads(ks *selectors.KernelSelectorState, index uint32) []*program.MapLoad {
	selBuff := ks.Buffer()
	maps := []*program.MapLoad{
		{
			Index: index,
			Name:  "filter_map",
			Load: func(m *ebpf.Map, _ string, index uint32) error {
				return m.Update(index, selBuff[:], ebpf.UpdateAny)
			},
		}, {
			Index: 0,
			Name:  "argfilter_maps",
			Load: func(outerMap *ebpf.Map, pinPathPrefix string, _ uint32) error {
				return populateArgFilterMaps(ks, pinPathPrefix, outerMap)
			},
		}, {
			Index: 0,
			Name:  "addr4lpm_maps",
			Load: func(outerMap *ebpf.Map, pinPathPrefix string, _ uint32) error {
				return populateAddr4FilterMaps(ks, pinPathPrefix, outerMap)
			},
		}, {
			Index: 0,
			Name:  "addr6lpm_maps",
			Load: func(outerMap *ebpf.Map, pinPathPrefix string, _ uint32) error {
				return populateAddr6FilterMaps(ks, pinPathPrefix, outerMap)
			},
		}, {
			Index: 0,
			Name:  "tg_mb_sel_opts",
			Load: func(outerMap *ebpf.Map, _ string, _ uint32) error {
				return populateMatchBinariesMaps(ks, outerMap)
			},
		}, {
			Index: 0,
			Name:  "tg_mb_paths",
			Load: func(outerMap *ebpf.Map, pinPathPrefix string, _ uint32) error {
				return populateMatchBinariesPathsMaps(ks, pinPathPrefix, outerMap)
			},
		}, {
			Index: 0,
			Name:  "string_prefix_maps",
			Load: func(outerMap *ebpf.Map, pinPathPrefix string, _ uint32) error {
				return populateStringPrefixFilterMaps(ks, pinPathPrefix, outerMap)
			},
		}, {
			Index: 0,
			Name:  "string_postfix_maps",
			Load: func(outerMap *ebpf.Map, pinPathPrefix string, _ uint32) error {
				return populateStringPostfixFilterMaps(ks, pinPathPrefix, outerMap)
			},
		}, {
			Index: 0,
			Name:  "string_maps_0",
			Load: func(outerMap *ebpf.Map, pinPathPrefix string, _ uint32) error {
				return populateStringFilterMaps(ks, pinPathPrefix, outerMap, 0)
			},
		}, {
			Index: 0,
			Name:  "string_maps_1",
			Load: func(outerMap *ebpf.Map, pinPathPrefix string, _ uint32) error {
				return populateStringFilterMaps(ks, pinPathPrefix, outerMap, 1)
			},
		}, {
			Index: 0,
			Name:  "string_maps_2",
			Load: func(outerMap *ebpf.Map, pinPathPrefix string, _ uint32) error {
				return populateStringFilterMaps(ks, pinPathPrefix, outerMap, 2)
			},
		}, {
			Index: 0,
			Name:  "string_maps_3",
			Load: func(outerMap *ebpf.Map, pinPathPrefix string, _ uint32) error {
				return populateStringFilterMaps(ks, pinPathPrefix, outerMap, 3)
			},
		}, {
			Index: 0,
			Name:  "string_maps_4",
			Load: func(outerMap *ebpf.Map, pinPathPrefix string, _ uint32) error {
				return populateStringFilterMaps(ks, pinPathPrefix, outerMap, 4)
			},
		}, {
			Index: 0,
			Name:  "string_maps_5",
			Load: func(outerMap *ebpf.Map, pinPathPrefix string, _ uint32) error {
				return populateStringFilterMaps(ks, pinPathPrefix, outerMap, 5)
			},
		}, {
			Index: 0,
			Name:  "string_maps_6",
			Load: func(outerMap *ebpf.Map, pinPathPrefix string, _ uint32) error {
				return populateStringFilterMaps(ks, pinPathPrefix, outerMap, 6)
			},
		}, {
			Index: 0,
			Name:  "string_maps_7",
			Load: func(outerMap *ebpf.Map, pinPathPrefix string, _ uint32) error {
				return populateStringFilterMaps(ks, pinPathPrefix, outerMap, 7)
			},
		},
	}
	if kernels.MinKernelVersion("5.11") {
		maps = append(maps, []*program.MapLoad{
			{
				Index: 0,
				Name:  "string_maps_8",
				Load: func(outerMap *ebpf.Map, pinPathPrefix string, _ uint32) error {
					return populateStringFilterMaps(ks, pinPathPrefix, outerMap, 8)
				},
			}, {
				Index: 0,
				Name:  "string_maps_9",
				Load: func(outerMap *ebpf.Map, pinPathPrefix string, _ uint32) error {
					return populateStringFilterMaps(ks, pinPathPrefix, outerMap, 9)
				},
			}, {
				Index: 0,
				Name:  "string_maps_10",
				Load: func(outerMap *ebpf.Map, pinPathPrefix string, _ uint32) error {
					return populateStringFilterMaps(ks, pinPathPrefix, outerMap, 10)
				},
			},
		}...)
	}
	return maps
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
	innerData map[selectors.KernelLPMTrie4]struct{},
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
	innerData map[selectors.KernelLPMTrie6]struct{},
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

func populateStringFilterMaps(
	k *selectors.KernelSelectorState,
	pinPathPrefix string,
	outerMap *ebpf.Map,
	subMap int,
) error {
	maxEntries := k.StringMapsMaxEntries(subMap)
	for i, am := range k.StringMaps(subMap) {
		nrEntries := uint32(len(am))
		// Versions before 5.9 do not allow inner maps to have different sizes.
		// See: https://lore.kernel.org/bpf/20200828011800.1970018-1-kafai@fb.com/
		if !kernels.MinKernelVersion("5.9") {
			nrEntries = uint32(maxEntries)
		}
		err := populateStringFilterMap(pinPathPrefix, outerMap, subMap, uint32(i), am, nrEntries)
		if err != nil {
			return err
		}
	}
	return nil
}

func populateStringFilterMap(
	pinPathPrefix string,
	outerMap *ebpf.Map,
	subMap int,
	innerID uint32,
	innerData map[[selectors.MaxStringMapsSize]byte]struct{},
	maxEntries uint32,
) error {
	mapKeySize := selectors.StringMapsSizes[subMap]
	if subMap == 7 && !kernels.MinKernelVersion("5.11") {
		mapKeySize = selectors.StringMapSize7a
	}
	innerName := fmt.Sprintf("string_maps_%d_%d", subMap, innerID)
	innerSpec := &ebpf.MapSpec{
		Name:       innerName,
		Type:       ebpf.Hash,
		KeySize:    uint32(mapKeySize),
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
	for rawVal := range innerData {
		val := rawVal[:mapKeySize]
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

func populateMatchBinariesMaps(
	ks *selectors.KernelSelectorState,
	bpfMap *ebpf.Map,
) error {
	for selID, sel := range ks.MatchBinaries() {
		if err := bpfMap.Update(uint32(selID), sel, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("failed to insert %v: %w", sel, err)
		}
	}
	return nil
}

func populateMatchBinariesPathsMaps(
	k *selectors.KernelSelectorState,
	pinPathPrefix string,
	outerMap *ebpf.Map,
) error {
	maxEntriesFromAllSelector := k.MatchBinariesPathsMaxEntries()
	matchBinaries := k.MatchBinaries()
	for selectorID, paths := range k.MatchBinariesPaths() {
		maxEntries := len(paths)
		// Versions before 5.9 do not allow inner maps to have different sizes.
		// See: https://lore.kernel.org/bpf/20200828011800.1970018-1-kafai@fb.com/
		if !kernels.MinKernelVersion("5.9") {
			maxEntries = maxEntriesFromAllSelector
		}

		innerName := fmt.Sprintf("tg_mb_path_%d", selectorID)
		innerSpec := &ebpf.MapSpec{
			Name:       innerName,
			Type:       ebpf.Hash,
			KeySize:    uint32(processapi.BINARY_PATH_MAX_LEN),
			ValueSize:  uint32(1),
			MaxEntries: uint32(maxEntries),
		}
		innerMap, err := ebpf.NewMapWithOptions(innerSpec, ebpf.MapOptions{
			PinPath: sensors.PathJoin(pinPathPrefix, innerName),
		})
		if err != nil {
			return fmt.Errorf("creating innerMap %s failed: %w", innerName, err)
		}
		defer innerMap.Close()

		for _, path := range paths {
			err := innerMap.Update(path, uint8(1), 0)
			if err != nil {
				return fmt.Errorf("failed to insert value into %s: %w", innerName, err)
			}
		}

		if err := outerMap.Update(uint32(selectorID), uint32(innerMap.FD()), 0); err != nil {
			return fmt.Errorf("failed to insert %s: %w", innerName, err)
		}

		mbSelector := matchBinaries[selectorID]
		if mbSelector.MBSetID != mbset.InvalidID {
			if err := mbset.UpdateMap(mbSelector.MBSetID, paths); err != nil {
				return fmt.Errorf("updating mbset map failed: %w", err)
			}
		}
	}
	return nil
}

func populateStringPrefixFilterMaps(
	k *selectors.KernelSelectorState,
	pinPathPrefix string,
	outerMap *ebpf.Map,
) error {
	maxEntries := k.StringPrefixMapsMaxEntries()
	for i, am := range k.StringPrefixMaps() {
		nrEntries := uint32(len(am))
		// Versions before 5.9 do not allow inner maps to have different sizes.
		// See: https://lore.kernel.org/bpf/20200828011800.1970018-1-kafai@fb.com/
		if !kernels.MinKernelVersion("5.9") {
			nrEntries = uint32(maxEntries)
		}
		err := populateStringPrefixFilterMap(pinPathPrefix, outerMap, uint32(i), am, nrEntries)
		if err != nil {
			return err
		}
	}
	return nil
}

func populateStringPrefixFilterMap(
	pinPathPrefix string,
	outerMap *ebpf.Map,
	innerID uint32,
	innerData map[selectors.KernelLPMTrieStringPrefix]struct{},
	maxEntries uint32,
) error {
	innerName := fmt.Sprintf("string_prefix_map_%d", innerID)
	innerSpec := &ebpf.MapSpec{
		Name:       innerName,
		Type:       ebpf.LPMTrie,
		KeySize:    4 + selectors.StringPrefixMaxLength, // NB: KernelLpmTrieStringPrefix consists of 32bit prefix and 256 byte data
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

func populateStringPostfixFilterMaps(
	k *selectors.KernelSelectorState,
	pinPathPrefix string,
	outerMap *ebpf.Map,
) error {
	maxEntries := k.StringPostfixMapsMaxEntries()
	for i, am := range k.StringPostfixMaps() {
		nrEntries := uint32(len(am))
		// Versions before 5.9 do not allow inner maps to have different sizes.
		// See: https://lore.kernel.org/bpf/20200828011800.1970018-1-kafai@fb.com/
		if !kernels.MinKernelVersion("5.9") {
			nrEntries = uint32(maxEntries)
		}
		err := populateStringPostfixFilterMap(pinPathPrefix, outerMap, uint32(i), am, nrEntries)
		if err != nil {
			return err
		}
	}
	return nil
}

func populateStringPostfixFilterMap(
	pinPathPrefix string,
	outerMap *ebpf.Map,
	innerID uint32,
	innerData map[selectors.KernelLPMTrieStringPostfix]struct{},
	maxEntries uint32,
) error {
	innerName := fmt.Sprintf("string_postfix_map_%d", innerID)
	innerSpec := &ebpf.MapSpec{
		Name:       innerName,
		Type:       ebpf.LPMTrie,
		KeySize:    4 + selectors.StringPostfixMaxLength, // NB: KernelLpmTrieStringPostfix consists of 32bit prefix and 128 byte data
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
