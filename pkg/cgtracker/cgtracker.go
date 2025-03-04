// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package cgtracker

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/cgroups"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
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

	if !option.Config.EnableCgTrackerID {
		return sensor, nil
	}

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

	trackerProgs := []*program.Program{mkdirProg, releaseProg}
	for _, p := range sensor.Progs {
		if base.IsExecve(p) || base.IsFork(p) || base.IsExit(p) {
			trackerProgs = append(trackerProgs, p)
		}
	}

	cgTrackerMap := program.MapBuilder(MapName, trackerProgs...)
	cgTrackerMap.SetMaxEntries(MapEntries)

	sensor.Progs = append(sensor.Progs, mkdirProg, releaseProg)
	sensor.Maps = append(sensor.Maps, cgTrackerMap)
	return sensor, nil
}

func init() {
	base.RegisterExtensionAtInit("cgroup_tracker", RegisterCgroupTracker)
}

var (
	glMap    Map
	glError  error
	setGlMap sync.Once
)

func globalMap() (Map, error) {
	setGlMap.Do(func() {
		retries := 0
		log := logger.GetLogger()
		// NB(kkourt): the map is needed for criResolver that runs in a new goroutine
		// started by newCriResolver. This goroutine will start before the base sensor which
		// initialized the map and, as a result, criResolver fails. To address this, add a
		// number of retries before we start.
		for {
			fname := filepath.Join(bpf.MapPrefixPath(), MapName)
			glMap, glError = OpenMap(fname)
			if glError == nil {
				log.Info("cgtracker map initialized")
				return
			} else if retries > 5 {
				log.WithError(glError).WithField("fname", fname).WithField("retries", retries).Warn("cgtracker map initialization failed")
			}
			time.Sleep(500 * time.Millisecond)
			retries++
		}
	})
	return glMap, glError
}

func AddCgroupTrackerPath(cgRoot string) error {
	m, err := globalMap()
	if err != nil {
		return err
	}
	return m.AddCgroupTrackerPath(cgRoot)
}

func Lookup(cgID uint64) (uint64, error) {
	m, err := globalMap()
	if err != nil {
		return 0, err
	}

	var ret uint64
	err = m.Lookup(&cgID, &ret)
	return ret, err
}
