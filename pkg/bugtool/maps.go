// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package bugtool

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"golang.org/x/exp/maps"
)

type ExtendedMapInfo struct {
	ebpf.MapInfo
	Memlock int
}

// TotalByteMemlock iterates over the extend map info and sums the memlock field.
func TotalByteMemlock(infos []ExtendedMapInfo) int {
	var sum int
	for _, info := range infos {
		sum += info.Memlock
	}
	return sum
}

// FindMapsUsedByPinnedProgs returns all info of maps used by the prog pinned
// under the path specified as argument. It also retrieve all the maps
// referenced in progs referenced in program array maps (tail calls).
func FindMapsUsedByPinnedProgs(path string) ([]ExtendedMapInfo, error) {
	mapIDs, err := mapIDsFromPinnedProgs(path)
	if err != nil {
		return nil, fmt.Errorf("failed retrieving map IDs: %w", err)
	}
	mapInfos := []ExtendedMapInfo{}
	for _, mapID := range mapIDs {
		memlockInfo, err := memlockInfoFromMapID(mapID)
		if err != nil {
			return nil, fmt.Errorf("failed retrieving map memlock from ID: %w", err)
		}
		mapInfos = append(mapInfos, memlockInfo)
	}
	return mapInfos, nil
}

// FindAllMaps iterates over all maps loaded on the host using MapGetNextID and
// parses fdinfo to look for memlock.
func FindAllMaps() ([]ExtendedMapInfo, error) {
	var mapID ebpf.MapID
	var err error
	mapInfos := []ExtendedMapInfo{}

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

		memlock, err := parseMemlockFromFDInfo(m.FD())
		if err != nil {
			return nil, fmt.Errorf("failed parsing fdinfo to retrieve memlock: %w", err)
		}

		mapInfos = append(mapInfos, ExtendedMapInfo{
			MapInfo: *info,
			Memlock: memlock,
		})
	}
}

// FindPinnedMaps returns all info of maps pinned under the path
// specified as argument.
func FindPinnedMaps(path string) ([]ExtendedMapInfo, error) {
	var infos []ExtendedMapInfo
	err := filepath.WalkDir(path, func(path string, d fs.DirEntry, _ error) error {
		if d.IsDir() {
			return nil // skip directories
		}
		m, err := ebpf.LoadPinnedMap(path, &ebpf.LoadPinOptions{
			ReadOnly: true,
		})
		if err != nil {
			return fmt.Errorf("failed to load pinned map %q: %w", path, err)
		}
		defer m.Close()

		// check if it's really a map because ebpf.LoadPinnedMap does not return
		// an error but garbage info on doing this on a prog
		if ok, err := isMap(m.FD()); err != nil || !ok {
			if err != nil {
				return err
			}
			return nil // skip non map
		}

		info, err := m.Info()
		if err != nil {
			return fmt.Errorf("failed to retrieve map info: %w", err)
		}

		memlock, err := parseMemlockFromFDInfo(m.FD())
		if err != nil {
			return fmt.Errorf("failed to parse memlock from fd (%d) info: %w", m.FD(), err)
		}

		infos = append(infos, ExtendedMapInfo{
			MapInfo: *info,
			Memlock: memlock,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return infos, nil
}

// mapIDsFromProgs retrieves all map IDs used inside a prog.
func mapIDsFromProgs(prog *ebpf.Program) ([]int, error) {
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
func mapIDsFromPinnedProgs(path string) ([]int, error) {
	mapSet := map[int]bool{}
	progArrays := []*ebpf.Map{}
	err := filepath.WalkDir(path, func(path string, d fs.DirEntry, _ error) error {
		if d.IsDir() {
			return nil // skip directories
		}
		prog, err := ebpf.LoadPinnedProgram(path, &ebpf.LoadPinOptions{
			ReadOnly: true,
		})
		if err != nil {
			return fmt.Errorf("failed to load pinned object %q: %w", path, err)
		}
		defer prog.Close()

		if ok, err := isProg(prog.FD()); err != nil || !ok {
			if err != nil {
				return err
			}

			// we want to keep a ref to prog array containing tail calls to
			// search reference to map inside
			ok, err := isMap(prog.FD())
			if err != nil {
				return err
			}
			if ok {
				m, err := ebpf.LoadPinnedMap(path, &ebpf.LoadPinOptions{
					ReadOnly: true,
				})
				if err != nil {
					return fmt.Errorf("failed to load pinned map %q: %w", path, err)
				}
				if m.Type() == ebpf.ProgramArray {
					progArrays = append(progArrays, m)
					// don't forget to close those files when used later on
				} else {
					m.Close()
				}
			}

			return nil // skip the non-prog
		}

		newIDs, err := mapIDsFromProgs(prog)
		if err != nil {
			return fmt.Errorf("failed to retrieve map IDs from prog: %w", err)
		}
		for _, id := range newIDs {
			mapSet[id] = true
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
		for _, id := range newIDs {
			mapSet[id] = true
		}
	}

	return maps.Keys(mapSet), nil
}

func memlockInfoFromMapID(id int) (ExtendedMapInfo, error) {
	m, err := ebpf.NewMapFromID(ebpf.MapID(id))
	if err != nil {
		return ExtendedMapInfo{}, fmt.Errorf("failed creating a map FD from ID: %w", err)
	}
	defer m.Close()
	memlock, err := parseMemlockFromFDInfo(m.FD())
	if err != nil {
		return ExtendedMapInfo{}, fmt.Errorf("failed parsing fdinfo for memlock: %w", err)
	}
	info, err := m.Info()
	if err != nil {
		return ExtendedMapInfo{}, fmt.Errorf("failed retrieving info from map: %w", err)
	}

	return ExtendedMapInfo{
		MapInfo: *info,
		Memlock: memlock,
	}, nil
}

func parseMemlockFromFDInfo(fd int) (int, error) {
	path := fmt.Sprintf("/proc/self/fdinfo/%d", fd)
	file, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("failed to open file %q: %w", path, err)
	}
	defer file.Close()
	return parseMemlockFromFDInfoReader(file)
}

func parseMemlockFromFDInfoReader(r io.Reader) (int, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) > 1 && fields[0] == "memlock:" {
			memlock, err := strconv.Atoi(fields[1])
			if err != nil {
				return 0, fmt.Errorf("failed converting memlock to int: %w", err)
			}
			return memlock, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("failed to scan: %w", err)
	}
	return 0, fmt.Errorf("didn't find memlock field")
}

func isProg(fd int) (bool, error) {
	return isBPFObject("prog", fd)
}

func isMap(fd int) (bool, error) {
	return isBPFObject("map", fd)
}

func isBPFObject(object string, fd int) (bool, error) {
	readlink, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return false, fmt.Errorf("failed to readlink the fd (%d): %w", fd, err)
	}
	return readlink == fmt.Sprintf("anon_inode:bpf-%s", object), nil
}
