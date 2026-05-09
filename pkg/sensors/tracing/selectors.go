// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

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
			Name: "filter_map",
			Load: func(m *ebpf.Map, _ string) error {
				return m.Update(index, selBuff[:], ebpf.UpdateAny)
			},
		},
	}
	if len(ks.ValueMaps()) != 0 {
		maps = append(maps, &program.MapLoad{
			Name: "argfilter_maps",
			Load: func(outerMap *ebpf.Map, pinPathPrefix string) error {
				return populateArgFilterMaps(ks, pinPathPrefix, outerMap)
			},
		})
	}
	if len(ks.Addr4Maps()) != 0 {
		maps = append(maps, &program.MapLoad{
			Name: "addr4lpm_maps",
			Load: func(outerMap *ebpf.Map, pinPathPrefix string) error {
				return populateAddr4FilterMaps(ks, pinPathPrefix, outerMap)
			},
		})
	}
	if len(ks.Addr6Maps()) != 0 {
		maps = append(maps, &program.MapLoad{
			Name: "addr6lpm_maps",
			Load: func(outerMap *ebpf.Map, pinPathPrefix string) error {
				return populateAddr6FilterMaps(ks, pinPathPrefix, outerMap)
			},
		})
	}
	if len(ks.MatchBinaries()) != 0 {
		maps = append(maps, &program.MapLoad{
			Name: "tg_mb_sel_opts",
			Load: func(outerMap *ebpf.Map, _ string) error {
				return populateMatchBinariesMaps(ks, outerMap)
			},
		})
	}
	if len(ks.MatchBinariesPaths()) != 0 {
		maps = append(maps, &program.MapLoad{
			Name: "tg_mb_paths",
			Load: func(outerMap *ebpf.Map, pinPathPrefix string) error {
				return populateMatchBinariesPathsMaps(ks, pinPathPrefix, outerMap)
			},
		})
	}
	if len(ks.StringPrefixMaps()) != 0 {
		maps = append(maps, &program.MapLoad{
			Name: "string_prefix_maps",
			Load: func(outerMap *ebpf.Map, pinPathPrefix string) error {
				return populateStringPrefixFilterMaps(ks, pinPathPrefix, outerMap)
			},
		})
	}
	if len(ks.StringPostfixMaps()) != 0 {
		maps = append(maps, &program.MapLoad{
			Name: "string_postfix_maps",
			Load: func(outerMap *ebpf.Map, pinPathPrefix string) error {
				return populateStringPostfixFilterMaps(ks, pinPathPrefix, outerMap)
			},
		})
	}
	numSubMaps := selectors.StringMapsNumSubMaps
	if !kernels.MinKernelVersion("5.11") {
		numSubMaps = selectors.StringMapsNumSubMapsSmall
	}
	for stringMapIndex := range numSubMaps {
		if len(ks.StringMaps(stringMapIndex)) == 0 {
			continue
		}
		idx := stringMapIndex
		maps = append(maps, &program.MapLoad{
			Name: fmt.Sprintf("string_maps_%d", idx),
			Load: func(outerMap *ebpf.Map, pinPathPrefix string) error {
				return populateStringFilterMaps(ks, pinPathPrefix, outerMap, idx)
			},
		})
	}
	if len(ks.SubStrings()) != 0 {
		maps = append(maps, &program.MapLoad{
			Name: "substring_map",
			Load: func(outerMap *ebpf.Map, _ string) error {
				return populateSubStringMap(outerMap, ks)
			},
		})
	}
	return maps
}

func populateSubStringMap(m *ebpf.Map, k *selectors.KernelSelectorState) error {
	for idx, ss := range k.SubStrings() {
		dst := make([]byte, 100)
		copy(dst, ss[:])

		if err := m.Update(uint32(idx), dst, ebpf.UpdateAny); err != nil {
			return err
		}
	}
	return nil
}

func createSelectorMaps(load *program.Program, state *selectors.KernelSelectorState) []*program.Map {
	var maps []*program.Map

	argFilterMaps := program.MapBuilderProgram("argfilter_maps", load)
	if state != nil && !kernels.MinKernelVersion("5.9") {
		// Versions before 5.9 do not allow inner maps to have different sizes.
		// See: https://lore.kernel.org/bpf/20200828011800.1970018-1-kafai@fb.com/
		maxEntries := state.ValueMapsMaxEntries()
		argFilterMaps.SetInnerMaxEntries(maxEntries)
	}
	maps = append(maps, argFilterMaps)

	addr4FilterMaps := program.MapBuilderProgram("addr4lpm_maps", load)
	if state != nil && !kernels.MinKernelVersion("5.9") {
		// Versions before 5.9 do not allow inner maps to have different sizes.
		// See: https://lore.kernel.org/bpf/20200828011800.1970018-1-kafai@fb.com/
		maxEntries := state.Addr4MapsMaxEntries()
		addr4FilterMaps.SetInnerMaxEntries(maxEntries)
	}
	maps = append(maps, addr4FilterMaps)

	addr6FilterMaps := program.MapBuilderProgram("addr6lpm_maps", load)
	if state != nil && !kernels.MinKernelVersion("5.9") {
		// Versions before 5.9 do not allow inner maps to have different sizes.
		// See: https://lore.kernel.org/bpf/20200828011800.1970018-1-kafai@fb.com/
		maxEntries := state.Addr6MapsMaxEntries()
		addr6FilterMaps.SetInnerMaxEntries(maxEntries)
	}
	maps = append(maps, addr6FilterMaps)

	var stringFilterMap [selectors.StringMapsNumSubMaps]*program.Map
	numSubMaps := selectors.StringMapsNumSubMaps
	if !kernels.MinKernelVersion("5.11") {
		numSubMaps = selectors.StringMapsNumSubMapsSmall
	}

	for stringMapIndex := range numSubMaps {
		stringFilterMap[stringMapIndex] = program.MapBuilderProgram(fmt.Sprintf("string_maps_%d", stringMapIndex), load)
		if state != nil && !kernels.MinKernelVersion("5.9") {
			// Versions before 5.9 do not allow inner maps to have different sizes.
			// See: https://lore.kernel.org/bpf/20200828011800.1970018-1-kafai@fb.com/
			maxEntries := state.StringMapsMaxEntries(stringMapIndex)
			stringFilterMap[stringMapIndex].SetInnerMaxEntries(maxEntries)
		}
		maps = append(maps, stringFilterMap[stringMapIndex])
	}

	stringPrefixFilterMaps := program.MapBuilderProgram("string_prefix_maps", load)
	if state != nil && !kernels.MinKernelVersion("5.9") {
		// Versions before 5.9 do not allow inner maps to have different sizes.
		// See: https://lore.kernel.org/bpf/20200828011800.1970018-1-kafai@fb.com/
		maxEntries := state.StringPrefixMapsMaxEntries()
		stringPrefixFilterMaps.SetInnerMaxEntries(maxEntries)
	}
	maps = append(maps, stringPrefixFilterMaps)

	stringPostfixFilterMaps := program.MapBuilderProgram("string_postfix_maps", load)
	if state != nil && !kernels.MinKernelVersion("5.9") {
		// Versions before 5.9 do not allow inner maps to have different sizes.
		// See: https://lore.kernel.org/bpf/20200828011800.1970018-1-kafai@fb.com/
		maxEntries := state.StringPostfixMapsMaxEntries()
		stringPostfixFilterMaps.SetInnerMaxEntries(maxEntries)
	}
	maps = append(maps, stringPostfixFilterMaps)

	matchBinariesPaths := program.MapBuilderProgram("tg_mb_paths", load)
	if state != nil && !kernels.MinKernelVersion("5.9") {
		// Versions before 5.9 do not allow inner maps to have different sizes.
		// See: https://lore.kernel.org/bpf/20200828011800.1970018-1-kafai@fb.com/
		maxEntries := state.MatchBinariesPathsMaxEntries()
		matchBinariesPaths.SetInnerMaxEntries(maxEntries)
	}
	maps = append(maps, matchBinariesPaths)

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
