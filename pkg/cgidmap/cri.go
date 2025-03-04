// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package cgidmap

import (
	"container/list"
	"context"
	"path/filepath"
	"sync"

	"github.com/cilium/tetragon/pkg/cgroups"
	"github.com/cilium/tetragon/pkg/cgtracker"
	"github.com/cilium/tetragon/pkg/cri"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics/crimetrics"
	"github.com/cilium/tetragon/pkg/option"
)

// code for resolving missing cgroup ids by quering the CRI

const (
	// if, for whatever reason, we cannot talk to the CRI we dont want the queue to grow
	// unbounded. Hence, we only keep the last 128 unresolved ids added. If we manage to catch
	// up, subsequent sync updates from the pod hooks will ensure that the ids that were dropped
	// will be added if they are still alive.
	maxUnmappedIDs = 128
)

type criResolver struct {
	mu   sync.Mutex
	cond sync.Cond
	// unresolvedIDs implements a LIFO for unresolved IDs.
	unresolvedIDs *list.List
}

type unmappedID struct {
	podID  PodID
	contID ContainerID
}

func (c *criResolver) enqeue(unmappedIDs []unmappedID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	defer c.cond.Signal()

	// unmapped ids to be enqueued are larger than our capacity. Create a new list and add as
	// many as we  can.
	if len(unmappedIDs) >= maxUnmappedIDs {
		newL := list.New()
		for _, id := range unmappedIDs[:maxUnmappedIDs] {
			newL.PushFront(id)
		}
		c.unresolvedIDs = newL
		return
	}

	// remove IDs from the end that for which we don't have the capacity
	newCnt := len(unmappedIDs) + c.unresolvedIDs.Len()
	if newCnt > maxUnmappedIDs {
		for i := 0; i < (newCnt - maxUnmappedIDs); i++ {
			c.unresolvedIDs.Remove(c.unresolvedIDs.Back())
		}
	}

	for _, id := range unmappedIDs {
		c.unresolvedIDs.PushFront(id)
	}
}

func criResolve(m Map, id unmappedID) error {
	contID := id.contID

	ctx := context.Background()
	cli, err := cri.GetClient(ctx)
	if err != nil {
		return err
	}

	cgPath, err := cri.CgroupPath(ctx, cli, contID)
	if err != nil {
		return err
	}

	cgRoot, err := cgroups.HostCgroupRoot()
	if err != nil {
		return err
	}

	var getCgroupID func(string) (uint64, error)
	if option.Config.EnableCgTrackerID {
		getCgroupID = cgroups.GetCgroupIdFromPath
	} else {
		getCgroupID = cgroups.GetCgroupIDFromSubCgroup
	}

	path := filepath.Join(cgRoot, cgPath)
	cgID, err := getCgroupID(path)
	if err != nil {
		return err
	}

	if err := cgtracker.AddCgroupTrackerPath(path); err != nil {
		logger.GetLogger().WithField("cri-resolve", true).WithError(err).Warn("failed to add path to cgroup tracker")
	}
	m.Add(id.podID, id.contID, cgID)
	return nil
}

func newCriResolver(m Map) *criResolver {
	ret := &criResolver{
		unresolvedIDs: list.New(),
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
			err := criResolve(m, id)
			if err != nil {
				crimetrics.CriResolutionErrorsTotal.WithLabelValues().Inc()
				logger.GetLogger().WithError(err).Warn("criResolve failed")
			}
			crimetrics.CriResolutionsTotal.WithLabelValues().Inc()
			ret.mu.Lock()
		}

	}()

	return ret
}
