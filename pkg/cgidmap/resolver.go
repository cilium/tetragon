// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows && !nok8s

package cgidmap

import (
	"container/list"
	"fmt"
	"sync"

	"github.com/cilium/tetragon/pkg/cgroups"
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
// only part of resolution that differs between backends.
type containerPathFn func(unmappedID) (string, error)

type resolver struct {
	mu   sync.Mutex
	cond sync.Cond
	// unresolvedIDs implements a LIFO for unresolved IDs: a recent request is
	// more likely to still reflect the current state of the pod than an old one.
	unresolvedIDs *list.List

	m             Map
	containerPath containerPathFn
	// getCgroupID derives the cgroup id from a path. The choice depends only
	// on how cgidmap keys its map (EnableCgTrackerID), not on the backend.
	getCgroupID func(string) (uint64, error)
	// addCgTrackerPath registers a resolved path with the cgroup tracker.
	addCgTrackerPath func(string) error
	attempted        *metrics.Counter
	errored          *metrics.Counter
}

func newResolver(m Map, containerPath containerPathFn, addCgTrackerPath func(string) error,
	attempted, errored *metrics.Counter) *resolver {
	getCgroupID := cgroups.GetCgroupIDFromSubCgroup
	if option.Config.EnableCgTrackerID {
		getCgroupID = cgroups.GetCgroupIdFromPath
	}
	ret := &resolver{
		unresolvedIDs:    list.New(),
		m:                m,
		containerPath:    containerPath,
		getCgroupID:      getCgroupID,
		addCgTrackerPath: addCgTrackerPath,
		attempted:        attempted,
		errored:          errored,
	}
	ret.cond.L = &ret.mu

	go func() {
		ret.mu.Lock()
		defer ret.mu.Unlock()

		for {
			for ret.unresolvedIDs.Len() == 0 {
				ret.cond.Wait()
			}

			// grab one container id and try to resolve it
			elem := ret.unresolvedIDs.Front()
			ret.unresolvedIDs.Remove(elem)
			ret.mu.Unlock()
			id := elem.Value.(unmappedID)
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

	// unmapped ids to be enqueued are larger than our capacity. Create a new list and add as
	// many as we  can.
	if len(unmappedIDs) >= maxUnmappedIDs {
		newL := list.New()
		for _, id := range unmappedIDs[:maxUnmappedIDs] {
			newL.PushFront(id)
		}
		r.unresolvedIDs = newL
		return
	}

	// remove IDs from the end that for which we don't have the capacity
	newCnt := len(unmappedIDs) + r.unresolvedIDs.Len()
	if newCnt > maxUnmappedIDs {
		for range newCnt - maxUnmappedIDs {
			r.unresolvedIDs.Remove(r.unresolvedIDs.Back())
		}
	}

	for _, id := range unmappedIDs {
		r.unresolvedIDs.PushFront(id)
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

	if err := r.addCgTrackerPath(path); err != nil {
		logger.GetLogger().Warn("failed to add path to cgroup tracker", "cgidmap-resolve", true, logfields.Error, err)
	}
	r.m.Add(id.podID, id.contID, cgID)
	return nil
}
