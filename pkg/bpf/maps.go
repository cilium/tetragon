// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package bpf

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
)

type ExtendedMapInfo struct {
	ebpf.MapInfo
	Memlock int
}

func ExtendedInfoFromMapID(id int) (ExtendedMapInfo, error) {
	m, err := ebpf.NewMapFromID(ebpf.MapID(id))
	if err != nil {
		return ExtendedMapInfo{}, fmt.Errorf("failed creating a map FD from ID: %w", err)
	}
	defer m.Close()

	xInfo, err := ExtendedInfoFromMap(m)
	if err != nil {
		return ExtendedMapInfo{}, fmt.Errorf("failed to retrieve extended info from map %v: %w", m, err)
	}

	return xInfo, nil
}

func ExtendedInfoFromMap(m *ebpf.Map) (ExtendedMapInfo, error) {
	info, err := m.Info()
	if err != nil {
		return ExtendedMapInfo{}, fmt.Errorf("failed to retrieve map info: %w", err)
	}

	memlock, err := ParseMemlockFromFDInfo(m.FD())
	if err != nil {
		return ExtendedMapInfo{}, fmt.Errorf("failed to parse memlock from fd (%d) info: %w", m.FD(), err)
	}
	return ExtendedMapInfo{
		MapInfo: *info,
		Memlock: memlock,
	}, nil
}

func MemlockInfoFromMapID(id int) (ExtendedMapInfo, error) {
	m, err := ebpf.NewMapFromID(ebpf.MapID(id))
	if err != nil {
		return ExtendedMapInfo{}, fmt.Errorf("failed creating a map FD from ID: %w", err)
	}
	defer m.Close()
	memlock, err := ParseMemlockFromFDInfo(m.FD())
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

func ParseMemlockFromFDInfo(fd int) (int, error) {
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
	return 0, errors.New("didn't find memlock field")
}
