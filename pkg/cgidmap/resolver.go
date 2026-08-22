// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows && !nok8s

package cgidmap

import (
	"fmt"
	"slices"
	"sync"

	"github.com/cilium/tetragon/pkg/cgroups"
	"github.com/cilium/tetragon/pkg/cgtracker"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/option"
)

// asynchronous resolution of unmapped container ids to cgroup ids. The queue and
// worker are backend-agnostic; a backend only provides a containerPathFn (how to
// find a container's cgroup path) and metric counters.

const (
	// if, for whatever reason, we cannot resolve ids we dont want the queue to grow
	// unbounded. Hence, we only keep the last 128 unresolved ids added. If we manage to catch
	// up, subsequent sync updates from the pod hooks will ensure that the ids that were dropped
	// will be added if they are still alive.
	maxUnmappedIDs = 128
)

type unmappedID struct {
	podID  PodID
	contID ContainerID
}

// containerPathFn returns the absolute host cgroup path for a container. It is the
// only part of resolution that differs between the CRI and cgroupfs backends.
type containerPathFn func(unmappedID) (string, error)

type resolver struct {
	mu   sync.Mutex
	cond sync.Cond
	// unresolvedIDs holds pending ids, oldest first; the worker pops the
	// newest from the end (LIFO).
	unresolvedIDs []unmappedID

	m             Map
	containerPath containerPathFn
	// getCgroupID derives the cgroup id from a path. The choice depends only
	// on how cgidmap keys its map (EnableCgTrackerID), not on the backend.
	getCgroupID func(string) (uint64, error)
	attempted   *metrics.Counter
	errored     *metrics.Counter
}

func newResolver(m Map, containerPath containerPathFn, attempted, errored *metrics.Counter) *resolver {
	getCgroupID := cgroups.GetCgroupIDFromSubCgroup
	if option.Config.EnableCgTrackerID {
		getCgroupID = cgroups.GetCgroupIdFromPath
	}
	ret := &resolver{
		m:             m,
		containerPath: containerPath,
		getCgroupID:   getCgroupID,
		attempted:     attempted,
		errored:       errored,
	}
	ret.cond.L = &ret.mu

	go func() {
		ret.mu.Lock()
		defer ret.mu.Unlock()

		for {
			for len(ret.unresolvedIDs) == 0 {
				ret.cond.Wait()
			}

			// grab the most recently added id and try to resolve it
			id := ret.unresolvedIDs[len(ret.unresolvedIDs)-1]
			ret.unresolvedIDs = ret.unresolvedIDs[:len(ret.unresolvedIDs)-1]
			ret.mu.Unlock()
			if err := ret.resolve(id); err != nil {
				ret.errored.WithLabelValues().Inc()
				logger.GetLogger().Warn("cgidmap resolve failed",
					"pod-id", id.podID, "container-id", id.contID, logfields.Error, err)
			}
			ret.attempted.WithLabelValues().Inc()
			ret.mu.Lock()
		}
	}()

	return ret
}

func (r *resolver) enqueue(unmappedIDs []unmappedID) {
	r.mu.Lock()
	defer r.mu.Unlock()
	defer r.cond.Signal()

	// pod updates can repeat ids that are still waiting for resolution; skip
	// them so duplicates do not evict other pending ids.
	for _, id := range unmappedIDs {
		if slices.Contains(r.unresolvedIDs, id) {
			continue
		}
		r.unresolvedIDs = append(r.unresolvedIDs, id)
	}
	// drop the oldest ids over capacity. Dropped ids that are still alive get
	// re-added by subsequent pod hook sync updates.
	if dropped := len(r.unresolvedIDs) - maxUnmappedIDs; dropped > 0 {
		r.unresolvedIDs = slices.Delete(r.unresolvedIDs, 0, dropped)
		logger.GetLogger().Debug("cgidmap resolver queue is full, dropped oldest unresolved ids", "dropped", dropped)
	}
}

// resolve finds the cgroup id for an unmapped container and adds it to the map. The
// backend-specific part (finding the cgroup path) is provided by containerPath.
func (r *resolver) resolve(id unmappedID) error {
	path, err := r.containerPath(id)
	if err != nil {
		return fmt.Errorf("find container path: %w", err)
	}

	cgID, err := r.getCgroupID(path)
	if err != nil {
		return fmt.Errorf("get cgroup id: %w", err)
	}

	if err := cgtracker.AddCgroupTrackerPath(path); err != nil {
		logger.GetLogger().Warn("failed to add path to cgroup tracker", "cgidmap-resolve", true, logfields.Error, err)
	}
	r.m.Add(id.podID, id.contID, cgID)
	return nil
}
