// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package cgtracker

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/cgroups"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/base"
	"github.com/cilium/tetragon/pkg/sensors/program"

	"github.com/sirupsen/logrus"
)

const (
	MapEntries  = 16 * 1024
	MapName     = "tg_cgtracker_map"
	objFilename = "bpf_cgtracker.o"
)

// cgtracker map
type Map struct {
	*ebpf.Map
}

func OpenMap(fname string) (Map, error) {
	m, err := ebpf.LoadPinnedMap(fname, &ebpf.LoadPinOptions{})
	if err != nil {
		return Map{nil}, err
	}

	return Map{m}, nil
}

func (m *Map) Dump() (map[uint64][]uint64, error) {
	ret := make(map[uint64][]uint64)
	var key, val uint64
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		entry := ret[val]
		entry = append(entry, key)
		ret[val] = entry
	}

	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("error iterating cgtracker map: %w", err)
	}

	return ret, nil
}

func (m *Map) Add(tracked, tracker uint64) error {
	return m.Update(&tracked, &tracker, ebpf.UpdateAny)
}

func (m *Map) AddCgroupTrackerPath(trackerPath string) error {
	cgID, err := cgroups.GetCgroupIdFromPath(trackerPath)
	if err != nil {
		return fmt.Errorf("failed to get cgroup tracker id: %w", err)
	}

	if err := m.Update(&cgID, &cgID, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to update cgroup tracker map for id %d: %w", cgID, err)
	}

	var walkErr error
	filepath.WalkDir(trackerPath, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			if d == nil {
				return fmt.Errorf("cgrouptracker: failed to walk dir %s: %w", p, err)
			}
			return fs.SkipDir
		}
		if !d.IsDir() {
			return nil
		}

		if p == trackerPath {
			return nil
		}

		trackedID, err := cgroups.GetCgroupIdFromPath(p)
		if err != nil {
			walkErr = errors.Join(walkErr, fmt.Errorf("failed to read id from '%s': %w", p, err))
			return nil
		}

		merr := m.Update(&trackedID, &cgID, ebpf.UpdateAny)
		if merr != nil {
			walkErr = errors.Join(walkErr, fmt.Errorf("failed to update id (%d) for '%s': %w", trackedID, p, merr))
		}

		logger.GetLogger().WithFields(logrus.Fields{
			"tracked":      trackedID,
			"tracker":      cgID,
			"tracked path": p,
			"tracker path": trackerPath,
		}).Debug("added mapping")

		return nil
	})

	// NB: if we managed to insert something in the map, call it a success: log the failures and
	// do not return an error
	if walkErr != nil {
		logger.GetLogger().WithField("cgtracker", true).WithError(walkErr).Warn("failed to retrieve some the cgroup id for some paths")
	}
	return nil
}

func RegisterCgroupTracker(sensor *sensors.Sensor) (*sensors.Sensor, error) {

	// TODO: check if cgroup tracker is enabled

	basePolicy := ""
	if len(sensor.Progs) > 0 {
		basePolicy = sensor.Progs[0].Policy
	}

	mkdirProg := program.Builder(
		objFilename,
		"cgroup/cgroup_mkdir",
		"raw_tracepoint/cgroup_mkdir",
		"tg_cgtracker_cgroup_mkdir",
		"raw_tracepoint",
	).SetPolicy(basePolicy)
	releaseProg := program.Builder(
		objFilename,
		"cgroup/cgroup_release",
		"raw_tracepoint/cgroup_release",
		"tg_cgtracker_cgroup_release",
		"raw_tracepoint",
	).SetPolicy(basePolicy)

	cgTrackerMap := program.MapBuilder(MapName, mkdirProg, releaseProg)
	cgTrackerMap.SetMaxEntries(MapEntries)

	sensor.Progs = append(sensor.Progs, mkdirProg, releaseProg)
	sensor.Maps = append(sensor.Maps, cgTrackerMap)
	return sensor, nil
}

func init() {
	base.RegisterExtensionAtInit("cgroup_tracker", RegisterCgroupTracker)
}
