// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package bugtool

import (
	"errors"
	"fmt"
	"io/fs"
	"iter"
	"maps"
	"os"
	"slices"
	"sort"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/pin"
	"github.com/cilium/tetragon/pkg/bpf"
)

// TotalMemlockBytes iterates over the extend map info and sums the memlock field.
func TotalMemlockBytes(infos []bpf.ExtendedMapInfo) int {
	var sum int
	for _, info := range infos {
		sum += info.Memlock
	}
	return sum
}

// FindMapsUsedByPinnedProgs returns all info of maps used by the prog pinned
// under the path specified as argument. It also retrieve all the maps
// referenced in progs referenced in program array maps (tail calls).
func FindMapsUsedByPinnedProgs(path string) ([]bpf.ExtendedMapInfo, error) {
	mapIDs, err := mapIDsFromPinnedProgs(path)
	if err != nil {
		return nil, fmt.Errorf("failed retrieving map IDs: %w", err)
	}
	mapInfos := []bpf.ExtendedMapInfo{}
	for mapID := range mapIDs {
		memlockInfo, err := bpf.ExtendedInfoFromMapID(mapID)
		if err != nil {
			return nil, fmt.Errorf("failed retrieving map memlock from ID: %w", err)
		}
		mapInfos = append(mapInfos, memlockInfo)
	}
	return mapInfos, nil
}

// FindAllMaps iterates over all maps loaded on the host using MapGetNextID and
// parses fdinfo to look for memlock.
func FindAllMaps() ([]bpf.ExtendedMapInfo, error) {
	var mapID ebpf.MapID
	var err error
	mapInfos := []bpf.ExtendedMapInfo{}

	for {
		mapID, err = ebpf.MapGetNextID(mapID)
		if err != nil {
			if errors.Is(err, syscall.ENOENT) {
				return mapInfos, nil
			}
			return nil, fmt.Errorf("didn't receive ENOENT at the end of iteration: %w", err)
		}

		m, err := ebpf.NewMapFromID(mapID)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve map from ID: %w", err)
		}
		defer m.Close()
		info, err := m.Info()
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve map info: %w", err)
		}

		memlock, err := bpf.ParseMemlockFromFDInfo(m.FD())
		if err != nil {
			return nil, fmt.Errorf("failed parsing fdinfo to retrieve memlock: %w", err)
		}

		mapInfos = append(mapInfos, bpf.ExtendedMapInfo{
			MapInfo: *info,
			Memlock: memlock,
		})
	}
}

// FindPinnedMaps returns all info of maps pinned under the path
// specified as argument.
func FindPinnedMaps(path string) ([]bpf.ExtendedMapInfo, error) {
	var infos []bpf.ExtendedMapInfo

	err := pin.WalkDir(path, func(_ string, d fs.DirEntry, obj pin.Pinner, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil // skip directories
		}

		m, ok := obj.(*ebpf.Map)
		if !ok {
			return nil // skip non map
		}
		defer m.Close()

		xInfo, err := bpf.ExtendedInfoFromMap(m)
		if err != nil {
			return fmt.Errorf("failed to retrieve extended info from map %v: %w", m, err)
		}
		infos = append(infos, xInfo)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return infos, nil
}

// mapIDsFromProgs retrieves all map IDs used inside a prog.
func mapIDsFromProgs(prog *ebpf.Program) (iter.Seq[int], error) {
	if prog == nil {
		return nil, fmt.Errorf("prog is nil")
	}
	progInfo, err := prog.Info()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve prog info: %w", err)
	}
	// check if field is available
	ids, available := progInfo.MapIDs()
	if !available {
		return nil, fmt.Errorf("can't link prog to map IDs, field available from 4.15")
	}
	mapSet := map[int]bool{}
	for _, id := range ids {
		mapSet[int(id)] = true
	}
	return maps.Keys(mapSet), nil
}

// mapIDsFromPinnedProgs scan the given path and returns the map IDs used by the
// prog pinned under the path. It also retrieves the map IDs used by the prog
// referenced by program array maps (tail calls). This should only work from
// kernel 4.15.
func mapIDsFromPinnedProgs(path string) (iter.Seq[int], error) {
	mapSet := map[int]bool{}
	progArrays := []*ebpf.Map{}
	err := pin.WalkDir(path, func(_ string, d fs.DirEntry, obj pin.Pinner, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil // skip directories
		}

		switch typedObj := obj.(type) {
		case *ebpf.Program:
			newIDs, err := mapIDsFromProgs(typedObj)
			if err != nil {
				return fmt.Errorf("failed to retrieve map IDs from prog: %w", err)
			}
			typedObj.Close()
			for id := range newIDs {
				mapSet[id] = true
			}
		case *ebpf.Map:
			if typedObj.Type() == ebpf.ProgramArray {
				progArrays = append(progArrays, typedObj)
				// don't forget to close those files when used later on
			} else {
				typedObj.Close()
			}
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed walking the path %q: %w", path, err)
	}

	// retrieve all the program IDs from prog array maps
	progIDs := []int{}
	for _, progArray := range progArrays {
		if progArray == nil {
			return nil, fmt.Errorf("prog array reference is nil")
		}
		defer progArray.Close()

		var key, value uint32
		progArrayIterator := progArray.Iterate()
		for progArrayIterator.Next(&key, &value) {
			progIDs = append(progIDs, int(value))
			if err := progArrayIterator.Err(); err != nil {
				return nil, fmt.Errorf("failed to iterate over prog array map: %w", err)
			}
		}
	}

	// retrieve the map IDs from the prog array maps
	for _, progID := range progIDs {
		prog, err := ebpf.NewProgramFromID(ebpf.ProgramID(progID))
		if err != nil {
			return nil, fmt.Errorf("failed to create new program from id %d: %w", progID, err)
		}
		defer prog.Close()
		newIDs, err := mapIDsFromProgs(prog)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve map IDs from prog: %w", err)
		}
		for id := range newIDs {
			mapSet[id] = true
		}
	}

	return maps.Keys(mapSet), nil
}

const TetragonBPFFS = "/sys/fs/bpf/tetragon"

type DiffMap struct {
	ID           int    `json:"id,omitempty"`
	Name         string `json:"name,omitempty"`
	Type         string `json:"type,omitempty"`
	KeySize      int    `json:"key_size,omitempty"`
	ValueSize    int    `json:"value_size,omitempty"`
	MaxEntries   int    `json:"max_entries,omitempty"`
	MemlockBytes int    `json:"memlock_bytes,omitempty"`
}

type AggregatedMap struct {
	Name              string  `json:"name,omitempty"`
	Type              string  `json:"type,omitempty"`
	KeySize           int     `json:"key_size,omitempty"`
	ValueSize         int     `json:"value_size,omitempty"`
	MaxEntries        int     `json:"max_entries,omitempty"`
	Count             int     `json:"count,omitempty"`
	TotalMemlockBytes int     `json:"total_memlock_bytes,omitempty"`
	PercentOfTotal    float64 `json:"percent_of_total,omitempty"`
}

type MapsChecksOutput struct {
	TotalMemlockBytes struct {
		AllMaps         int `json:"all_maps,omitempty"`
		PinnedProgsMaps int `json:"pinned_progs_maps,omitempty"`
		PinnedMaps      int `json:"pinned_maps,omitempty"`
	} `json:"total_memlock_bytes,omitempty"`

	MapsStats struct {
		PinnedProgsMaps int `json:"pinned_progs_maps,omitempty"`
		PinnedMaps      int `json:"pinned_maps,omitempty"`
		Inter           int `json:"inter,omitempty"`
		Exter           int `json:"exter,omitempty"`
		Union           int `json:"union,omitempty"`
		Diff            int `json:"diff,omitempty"`
	} `json:"maps_stats,omitempty"`

	DiffMaps []DiffMap `json:"diff_maps,omitempty"`

	AggregatedMaps []AggregatedMap `json:"aggregated_maps,omitempty"`
}

func RunMapsChecks(path string) (*MapsChecksOutput, error) {
	// check that the bpffs exists and we have permissions
	_, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("make sure tetragon is running and you have enough permissions: %w", err)
	}

	// retrieve map infos
	allMaps, err := FindAllMaps()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve all maps: %w", err)
	}
	pinnedProgsMaps, err := FindMapsUsedByPinnedProgs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve maps used by pinned progs: %w", err)
	}
	pinnedMaps, err := FindPinnedMaps(path)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve pinned maps: %w", err)
	}

	var out MapsChecksOutput

	// BPF maps memory usage
	out.TotalMemlockBytes.AllMaps = TotalMemlockBytes(allMaps)
	out.TotalMemlockBytes.PinnedProgsMaps = TotalMemlockBytes(pinnedProgsMaps)
	out.TotalMemlockBytes.PinnedMaps = TotalMemlockBytes(pinnedMaps)

	// details on map distribution
	pinnedProgsMapsSet := map[int]bpf.ExtendedMapInfo{}
	for _, info := range pinnedProgsMaps {
		id, ok := info.ID()
		if !ok {
			return nil, errors.New("failed retrieving progs ID, need >= 4.13, kernel is too old")
		}
		pinnedProgsMapsSet[int(id)] = info
	}

	pinnedMapsSet := map[int]bpf.ExtendedMapInfo{}
	for _, info := range pinnedMaps {
		id, ok := info.ID()
		if !ok {
			return nil, errors.New("failed retrieving map ID, need >= 4.13, kernel is too old")
		}
		pinnedMapsSet[int(id)] = info
	}

	diff := diff(pinnedMapsSet, pinnedProgsMapsSet)
	union := union(pinnedMapsSet, pinnedProgsMapsSet)

	out.MapsStats.PinnedProgsMaps = len(pinnedProgsMapsSet)
	out.MapsStats.PinnedMaps = len(pinnedMaps)
	out.MapsStats.Inter = len(inter(pinnedMapsSet, pinnedProgsMapsSet))
	out.MapsStats.Exter = len(exter(pinnedMapsSet, pinnedProgsMapsSet))
	out.MapsStats.Union = len(union)
	out.MapsStats.Diff = len(diff)

	// details on diff maps
	for _, d := range diff {
		id, ok := d.ID()
		if !ok {
			return nil, errors.New("failed retrieving map ID, need >= 4.13, kernel is too old")
		}
		out.DiffMaps = append(out.DiffMaps, DiffMap{
			ID:           int(id),
			Name:         d.Name,
			Type:         d.Type.String(),
			KeySize:      int(d.KeySize),
			ValueSize:    int(d.ValueSize),
			MaxEntries:   int(d.MaxEntries),
			MemlockBytes: d.Memlock,
		})
	}

	// aggregates maps total memory use
	aggregatedMapsSet := map[string]struct {
		bpf.ExtendedMapInfo
		count int
	}{}
	var total int
	for _, m := range union {
		total += m.Memlock
		if e, exist := aggregatedMapsSet[m.Name]; exist {
			e.Memlock += m.Memlock
			e.count++
			aggregatedMapsSet[m.Name] = e
		} else {
			aggregatedMapsSet[m.Name] = struct {
				bpf.ExtendedMapInfo
				count int
			}{m, 1}
		}
	}
	aggregatedMaps := slices.Collect(maps.Values(aggregatedMapsSet))
	sort.Slice(aggregatedMaps, func(i, j int) bool {
		return aggregatedMaps[i].Memlock > aggregatedMaps[j].Memlock
	})

	for _, m := range aggregatedMaps {
		out.AggregatedMaps = append(out.AggregatedMaps, AggregatedMap{
			Name:              m.Name,
			Type:              m.Type.String(),
			KeySize:           int(m.KeySize),
			ValueSize:         int(m.ValueSize),
			MaxEntries:        int(m.MaxEntries),
			Count:             m.count,
			TotalMemlockBytes: m.Memlock,
			PercentOfTotal:    float64(m.Memlock) / float64(total) * 100,
		})
	}

	return &out, nil
}

func inter[T any](m1, m2 map[int]T) map[int]T {
	ret := map[int]T{}
	for i := range m1 {
		if _, exists := m2[i]; exists {
			ret[i] = m1[i]
		}
	}
	return ret
}

func diff[T any](m1, m2 map[int]T) map[int]T {
	ret := map[int]T{}
	for i := range m1 {
		if _, exists := m2[i]; !exists {
			ret[i] = m1[i]
		}
	}
	return ret
}

func exter[T any](m1, m2 map[int]T) map[int]T {
	ret := map[int]T{}
	for i := range m1 {
		if _, exists := m2[i]; !exists {
			ret[i] = m1[i]
		}
	}
	for i := range m2 {
		if _, exists := m1[i]; !exists {
			ret[i] = m2[i]
		}
	}
	return ret
}

func union[T any](m1, m2 map[int]T) map[int]T {
	ret := map[int]T{}
	for i := range m1 {
		ret[i] = m1[i]
	}
	for i := range m2 {
		ret[i] = m2[i]
	}
	return ret
}
