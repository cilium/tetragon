// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// package cgidcontmap contains code for mapping cgroup ids to container ids via the use of rthooks.
// The purpose of this is to allow better pod mapping, by using the cgroup id rather than the cgroup
// name to associate events and pods.

//go:build !windows

package cgidmap

import (
	"sync"

	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/cgtracker"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// convinience types to make APIs more readable
type CgroupID = uint64
type ContainerID = string
type PodID = uuid.UUID

// Map implements the a cgroup id to container id maping
//
// Its intended use is to associate pod information with events by using a cgroup id
// defined in the low-level event (bpf or proc) to find the container ID.
//
// The idea is:
//   - Get() is called by the pod-association code
//   - Add() is called to update the mapping. This can happen either in runtime hooks or by talking
//     to the CRI
//   - Update() is called to update the state of container / pods. This is called by the K8s pod
//     watcher.
type Map interface {
	// Get retrieves a container id based on a cgroup id
	Get(cgID CgroupID) (ContainerID, bool)

	// Add adds a <podID, contID, cgroupID> entry in the mapping
	Add(podID PodID, contID ContainerID, cgroupID CgroupID)

	// Update updates the state of pod and containers.
	// For example, previous container ids added for a certain pod will be removed if the
	// container ids are not in the provided list. Removing all information for a pod (e.g.,
	// when a pod is deleted) can be done by passing an empty list of container ids.
	Update(podID PodID, contIDs []ContainerID)
}

// map entry
type entry struct {
	cgID    CgroupID
	contID  ContainerID
	podID   PodID
	invalid bool
}

// cgidm implements Map
//
// cgidm holds a slice of <CgroupID,ContainerID,PodID,Invalid> entries.
// There are two maps that act as indices:
//   - cgMap maps cgroup ids to an index in the slice
//   - contMap maps container ids to an index in the slice
//
// Entries with the invalid bit set are considered free space and are not indexed in the above maps.
type cgidm struct {
	mu         sync.Mutex
	entries    []entry
	cgMap      map[CgroupID]int
	contMap    map[ContainerID]int
	invalidCnt int

	log logrus.FieldLogger
	*logger.DebugLogger

	criResolver *criResolver
}

func newMap() (*cgidm, error) {
	log := logger.GetLogger().WithField("cgidmap", true)

	m := &cgidm{
		entries:     make([]entry, 0, 1024),
		cgMap:       make(map[CgroupID]int),
		contMap:     make(map[ContainerID]int),
		log:         log,
		DebugLogger: logger.NewDebugLogger(log, option.Config.EnableCgIDmapDebug),
	}

	var criResolver *criResolver
	if option.Config.EnableCRI {
		criResolver = newCriResolver(m)
	} else {
		logger.GetLogger().Warn("cgidmap is enabled but cri is not. This means that pod association will not work for existing pods. You can enable cri using --enable-cri")
	}
	m.criResolver = criResolver
	return m, nil
}

// addEntryAllocID allocates space for a new entry, adds it, and returns its id
func (m *cgidm) addEntryAllocID(e entry) int {
	l := len(m.entries)
	// if we have free capacity in the slice or no invalid entries, append a new entry
	if cap(m.entries) > l || m.invalidCnt == 0 {
		m.entries = append(m.entries, e)
		return l
	}

	// otherwise, try to find an invalid entry to use
	for i := range m.entries {
		if m.entries[i].invalid {
			m.invalidCnt--
			m.entries[i] = e
			return i
		}
	}

	// this should not happen (tm)
	m.log.Warn("invalid count is wrong. Please report this message to Tetragon developers")
	m.entries = append(m.entries, e)
	return l
}

// addEntry adds a new entry, and updates the map indices
func (m *cgidm) addEntry(e entry) {
	idx := m.addEntryAllocID(e)
	m.contMap[e.contID] = idx
	m.cgMap[e.cgID] = idx
}

// updateEntry updates an existing entry
func (m *cgidm) updateEntry(idx int, newEntry entry) {
	oldEntry := &m.entries[idx]
	if oldEntry.podID != newEntry.podID {
		m.log.WithFields(logrus.Fields{
			"newEntry.podID": newEntry.podID,
			"oldEntry.podID": oldEntry.podID,
			"containerID":    newEntry.contID,
		}).Warn("invalid entry in cgidmap: mismatching pod id, please report this message to Tetragon developers")
		oldEntry.podID = newEntry.podID
	}

	if oldEntry.cgID != newEntry.cgID {
		m.log.WithFields(logrus.Fields{
			"podID":       newEntry.podID,
			"containerID": newEntry.contID,
			"newcgID":     newEntry.cgID,
			"oldcgID":     oldEntry.cgID,
		}).Warn("invalid entry in cgidmap: mismatching cg id, please report this message to Tetragon developers")
		oldEntry.cgID = newEntry.cgID
	}
}

// Add adds a new entry to the cgid map
func (m *cgidm) Add(podID PodID, contID ContainerID, cgroupID CgroupID) {
	m.DebugLogWithCallers(2).WithFields(logrus.Fields{
		"podID":    podID,
		"contID":   contID,
		"cgroupID": cgroupID,
	}).Info("cgidmap.Add")

	newEntry := entry{
		podID:  podID,
		contID: contID,
		cgID:   cgroupID,
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if idx, ok := m.contMap[contID]; ok {
		m.updateEntry(idx, newEntry)
		return
	}
	m.addEntry(newEntry)
}

func (m *cgidm) Get(cgID CgroupID) (ContainerID, bool) {
	m.DebugLogWithCallers(2).WithFields(logrus.Fields{
		"cgroupID": cgID,
	}).Debug("cgidmap.Get")

	m.mu.Lock()
	defer m.mu.Unlock()
	if idx, ok := m.cgMap[cgID]; ok {
		return m.entries[idx].contID, true
	}
	return "", false
}

// Update updates the cgid map for the container ids of a given pod
func (m *cgidm) Update(podID PodID, contIDs []ContainerID) {
	m.DebugLogWithCallers(2).WithFields(logrus.Fields{
		"podID":   podID,
		"contIDs": contIDs,
	}).Info("cgidmap.Update")

	tmp := make(map[ContainerID]struct{}, len(contIDs))
	for _, id := range contIDs {
		tmp[id] = struct{}{}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	for idx := range m.entries {
		e := &m.entries[idx]

		// skip invalid entries and entries from other pods
		if e.invalid || e.podID != podID {
			continue
		}

		// container is still part of the pod, leave it as is
		if _, ok := tmp[e.contID]; ok {
			delete(tmp, e.contID)
			continue
		}

		// container was removed from pod, remove the entry
		delete(m.cgMap, e.cgID)
		delete(m.contMap, e.contID)
		e.invalid = true
		m.invalidCnt++
	}

	// no remaining container ids, nothing more to do
	if len(tmp) == 0 {
		return
	}

	// schedule unmapped ids to be resolved by the CRI resolver
	unmappedIDs := make([]unmappedID, 0, len(tmp))
	for id := range tmp {
		unmappedIDs = append(unmappedIDs, unmappedID{
			podID:  podID,
			contID: id,
		})
	}
	if m.criResolver != nil {
		m.criResolver.enqeue(unmappedIDs)
	}
}

// Global state

var (
	glMap    *cgidm
	glError  error
	setGlMap sync.Once
)

type cgidDisabledTy struct{}

var cgidDisabled = &cgidDisabledTy{}

func (e *cgidDisabledTy) Error() string {
	return "cgidmap disabled"
}

// GlobalMap returns a global reference to the cgidmap
func GlobalMap() (Map, error) {
	setGlMap.Do(func() {
		if !option.Config.EnableCgIDmap {
			glMap = nil
			glError = cgidDisabled
			return
		}

		glMap, glError = newMap()
		if glError == nil {
			glMap.log.Info("cgidmap initialized")
		} else {
			glMap.log.WithError(glError).Warn("cgidmap initialization failed")
		}
	})
	return glMap, glError
}

func SetContainerID(info *processapi.MsgK8sUnix) {
	m, err := GlobalMap()
	if err != nil {
		logger.GetLogger().WithError(err).Warn("failed to get cgIdMap")
		return
	}

	cgID := info.Cgrpid
	if option.Config.EnableCgTrackerID {
		if info.CgrpTrackerID == 0 {
			// tracker id is not set. This can happen, for example, for
			// processes we get out of /proc. Let's try and resolve it if we can
			cgTrackerID, err := cgtracker.Lookup(info.Cgrpid)
			if err != nil {
				return
			}
			info.CgrpTrackerID = cgTrackerID
		}
		cgID = info.CgrpTrackerID
	}
	if containerID, ok := m.Get(cgID); ok {
		info.Docker = containerID
	}
}
