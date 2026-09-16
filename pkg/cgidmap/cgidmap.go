// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// package cgidcontmap contains code for mapping cgroup ids to container ids via the use of rthooks.
// The purpose of this is to allow better pod mapping, by using the cgroup id rather than the cgroup
// name to associate events and pods.

//go:build !windows && !nok8s

package cgidmap

import (
	"sync"
	"uuid"

	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/cgtracker"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/option"
)

// convinience types to make APIs more readable
type CgroupID = uint64
type ContainerID = string
type PodSandboxID = string
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

	// GetPodSandbox retrieves a pod sandbox id based on a cgroup id
	GetPodSandbox(cgID CgroupID) (PodSandboxID, bool)

	// Add adds a <podID, contID, cgroupID> entry in the mapping
	Add(podID PodID, contID ContainerID, cgroupID CgroupID)

	// AddPodSandbox adds a <podID, sandboxID, cgroupID> entry for a pod sandbox
	AddPodSandbox(podID PodID, sandboxID PodSandboxID, cgroupID CgroupID)

	// Update updates the state of pod and containers.
	// For example, previous container ids added for a certain pod will be removed if the
	// container ids are not in the provided list. Removing all information for a pod (e.g.,
	// when a pod is deleted) can be done by passing an empty list of container ids.
	Update(podID PodID, contIDs []ContainerID)

	// UpdatePodSandbox updates the state of pod sandbox.
	// If the sandboxID is different or empty, previous sandbox entries for the pod are removed.
	UpdatePodSandbox(podID PodID, sandboxID PodSandboxID)
}

// map entry
type entry[EntryID string] struct {
	cgID    CgroupID
	entryID EntryID
	podID   PodID
	invalid bool
}

type entryMap[EntryID string] struct {
	mu sync.Mutex

	entries    []entry[EntryID]
	cgMap      map[CgroupID]int
	entryMap   map[EntryID]int
	invalidCnt int
	isSandbox  bool

	log logger.FieldLogger
}

func newEntryMap[EntryID string](log logger.FieldLogger, isSandbox bool) *entryMap[EntryID] {
	return &entryMap[EntryID]{
		entries:    make([]entry[EntryID], 0, 1024),
		cgMap:      make(map[CgroupID]int),
		entryMap:   make(map[EntryID]int),
		invalidCnt: 0,
		log:        log,
		isSandbox:  isSandbox,
	}
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
	containerIDs  *entryMap[ContainerID]
	podSandboxIDs *entryMap[PodSandboxID]

	log logger.FieldLogger
	*logger.DebugLogger

	criResolver *criResolver
}

func newMap() (*cgidm, error) {
	log := logger.GetLogger().With("cgidmap", true)

	isSandbox := true
	m := &cgidm{
		containerIDs:  newEntryMap[ContainerID](log, !isSandbox),
		podSandboxIDs: newEntryMap[PodSandboxID](log, isSandbox),
		log:           log,
		DebugLogger:   logger.NewDebugLogger(log, option.Config.EnableCgIDmapDebug),
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
func (em *entryMap[EntryID]) addEntryAllocID(e entry[EntryID]) int {
	l := len(em.entries)
	// if we have free capacity in the slice or no invalid entries, append a new entry
	if cap(em.entries) > l || em.invalidCnt == 0 {
		em.entries = append(em.entries, e)
		return l
	}

	// otherwise, try to find an invalid entry to use
	for i := range em.entries {
		if em.entries[i].invalid {
			em.invalidCnt--
			em.entries[i] = e
			return i
		}
	}

	// this should not happen (tm)
	em.log.Warn("invalid count is wrong. Please report this message to Tetragon developers")
	em.entries = append(em.entries, e)
	return l
}

// addEntry adds a new entry, and updates the map indices
func (em *entryMap[EntryID]) addEntry(e entry[EntryID]) {
	idx := em.addEntryAllocID(e)
	em.entryMap[e.entryID] = idx
	em.cgMap[e.cgID] = idx
}

// updateEntry updates an existing entry
func (em *entryMap[EntryID]) updateEntry(idx int, newEntry entry[EntryID]) {
	oldEntry := &em.entries[idx]
	if oldEntry.podID != newEntry.podID {
		em.log.Warn("invalid entry in cgidmap: mismatching pod id, please report this message to Tetragon developers",
			"newEntry.podID", newEntry.podID,
			"oldEntry.podID", oldEntry.podID,
			"entryID", newEntry.entryID)
		oldEntry.podID = newEntry.podID
	}

	if oldEntry.cgID != newEntry.cgID {
		em.log.Warn("invalid entry in cgidmap: mismatching cg id, please report this message to Tetragon developers",
			"podID", newEntry.podID,
			"entryID", newEntry.entryID,
			"newcgID", newEntry.cgID,
			"oldcgID", oldEntry.cgID)
		oldEntry.cgID = newEntry.cgID
	}
}

func (em *entryMap[EntryID]) Add(podID PodID, entryID EntryID, cgroupID CgroupID) {
	newEntry := entry[EntryID]{
		podID:   podID,
		entryID: entryID,
		cgID:    cgroupID,
	}

	em.mu.Lock()
	defer em.mu.Unlock()
	if idx, ok := em.entryMap[entryID]; ok {
		em.updateEntry(idx, newEntry)
		return
	}
	em.addEntry(newEntry)
}

func (em *entryMap[EntryID]) Get(cgID CgroupID) (EntryID, bool) {
	em.mu.Lock()
	defer em.mu.Unlock()
	if idx, ok := em.cgMap[cgID]; ok {
		return em.entries[idx].entryID, true
	}
	return "", false
}

func (em *entryMap[EntryID]) Update(podID PodID, entryIDs []EntryID, criResolver *criResolver) {
	tmp := make(map[EntryID]struct{}, len(entryIDs))
	for _, id := range entryIDs {
		tmp[id] = struct{}{}
	}

	em.mu.Lock()
	defer em.mu.Unlock()
	for idx := range em.entries {
		e := &em.entries[idx]

		// skip invalid entries and entries from other pods
		if e.invalid || e.podID != podID {
			continue
		}

		// container is still part of the pod, leave it as is
		if _, ok := tmp[e.entryID]; ok {
			delete(tmp, e.entryID)
			continue
		}

		// container was removed from pod, remove the entry
		delete(em.cgMap, e.cgID)
		delete(em.entryMap, e.entryID)
		e.invalid = true
		em.invalidCnt++
	}

	// no remaining container ids, nothing more to do
	if len(tmp) == 0 {
		return
	}

	// schedule unmapped ids to be resolved by the CRI resolver
	unmappedIDs := make([]unmappedID, 0, len(tmp))
	for id := range tmp {
		unmappedIDs = append(unmappedIDs, unmappedID{
			podID:     podID,
			contID:    string(id),
			isSandbox: em.isSandbox,
		})
	}
	if criResolver != nil {
		criResolver.enqeue(unmappedIDs)
	}
}

// Add adds a new entry to the cgid map
func (m *cgidm) Add(podID PodID, contID ContainerID, cgroupID CgroupID) {
	m.DebugLogWithCallers(2).Info("cgidmap.Add", "podID", podID, "contID", contID, "cgroupID", cgroupID)

	m.containerIDs.Add(podID, contID, cgroupID)
}

// AddPodSandbox adds a new pod sandbox entry to the cgid map
func (m *cgidm) AddPodSandbox(podID PodID, sandboxID PodSandboxID, cgroupID CgroupID) {
	m.DebugLogWithCallers(2).Info("cgidmap.AddPodSandbox", "podID", podID, "sandboxID", sandboxID, "cgroupID", cgroupID)

	m.podSandboxIDs.Add(podID, sandboxID, cgroupID)
}

func (m *cgidm) Get(cgID CgroupID) (ContainerID, bool) {
	m.DebugLogWithCallers(2).Debug("cgidmap.Get", "cgroupID", cgID)

	return m.containerIDs.Get(cgID)
}

func (m *cgidm) GetPodSandbox(cgID CgroupID) (PodSandboxID, bool) {
	m.DebugLogWithCallers(2).Debug("cgidmap.GetPodSandbox", "cgroupID", cgID)

	return m.podSandboxIDs.Get(cgID)
}

// Update updates the cgid map for the container ids of a given pod
func (m *cgidm) Update(podID PodID, contIDs []ContainerID) {
	m.DebugLogWithCallers(2).Info("cgidmap.Update", "podID", podID, "contIDs", contIDs)

	m.containerIDs.Update(podID, contIDs, m.criResolver)
}

// UpdatePodSandbox updates the cgid map for the sandbox id of a given pod
func (m *cgidm) UpdatePodSandbox(podID PodID, sandboxID PodSandboxID) {
	m.DebugLogWithCallers(2).Info("cgidmap.UpdatePodSandbox", "podID", podID, "sandboxID", sandboxID)

	m.podSandboxIDs.Update(podID, []PodSandboxID{sandboxID}, m.criResolver)
}

// Global state

var (
	glMap    *cgidm
	glError  error // nolint:errname
	setGlMap sync.Once
)

type cgidDisabledError struct{}

var errCgidDisabled = &cgidDisabledError{}

func (e *cgidDisabledError) Error() string {
	return "cgidmap disabled"
}

// GlobalMap returns a global reference to the cgidmap
func GlobalMap() (Map, error) {
	setGlMap.Do(func() {
		if !option.Config.EnableCgIDmap {
			glMap = nil
			glError = errCgidDisabled
			return
		}

		glMap, glError = newMap()
		if glError == nil {
			glMap.log.Info("cgidmap initialized")
		} else {
			glMap.log.Warn("cgidmap initialization failed", logfields.Error, glError)
		}
	})
	return glMap, glError
}

func SetContainerID(info *processapi.MsgK8sUnix) {
	m, err := GlobalMap()
	if err != nil {
		logger.GetLogger().Warn("failed to get cgIdMap", logfields.Error, err)
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
