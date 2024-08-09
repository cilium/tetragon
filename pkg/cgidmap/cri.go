// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package cgidmap

import (
	"container/list"
	"context"
	"path/filepath"
	"sync"

	"github.com/cilium/tetragon/pkg/cgroups"
	"github.com/cilium/tetragon/pkg/cri"
	"github.com/cilium/tetragon/pkg/logger"
)

// code for resolving missing cgroup ids by quering the CRI

const (
	// if, for whatever reason, we cannot talk to the CRI we dont want the queue to grow
	// unbounded. Hence, we only keep the last 128 unresolved ids added. If we manage to catch
	// up, subsequent sync updates from the pod hooks will ensure that the ids that were dropped
	// will be added if they are still alive.
	maxUnmappedIds = 128
)

type criResolver struct {
	mu            sync.Mutex
	cond          sync.Cond
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

	if len(unmappedIDs) >= maxUnmappedIds {
		newL := list.New()
		for _, id := range unmappedIDs[:maxUnmappedIds] {
			newL.PushFront(id)
		}
		c.unresolvedIDs = newL
		return
	}

	newCnt := len(unmappedIDs) + c.unresolvedIDs.Len()
	if newCnt > maxUnmappedIds {
		for i := 0; i < (newCnt - maxUnmappedIds); i++ {
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

	path := filepath.Join(cgRoot, cgPath)
	cgID, err := cgroups.GetCgroupIdFromCgroupPath(path)
	if err != nil {
		return err
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
				logger.GetLogger().WithError(err).Warn("criResolve failed")
			}
			ret.mu.Lock()
		}

	}()

	return ret
}
