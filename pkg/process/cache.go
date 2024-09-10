// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package process

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/logger"
	lru "github.com/hashicorp/golang-lru/v2"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type Cache struct {
	cache      *lru.Cache[string, *ProcessInternal]
	size       int
	deleteChan chan *ProcessInternal
	stopChan   chan bool
}

// garbage collection states
const (
	inUse = iota
	deletePending
	deleteReady
	deleted
)

var colorStr = map[int]string{
	inUse:         "inUse",
	deletePending: "deletePending",
	deleteReady:   "deleteReady",
	deleted:       "deleted",
}

// garbage collection run interval
const (
	intervalGC = time.Second * 30
)

func (pc *Cache) cacheGarbageCollector() {
	ticker := time.NewTicker(intervalGC)
	pc.deleteChan = make(chan *ProcessInternal)
	pc.stopChan = make(chan bool)

	go func() {
		var deleteQueue, newQueue []*ProcessInternal

		for {
			select {
			case <-pc.stopChan:
				ticker.Stop()
				pc.cache.Purge()
				return
			case <-ticker.C:
				newQueue = newQueue[:0]
				for _, p := range deleteQueue {
					/* If the ref != 0 this means we have bounced
					 * through !refcnt and now have a refcnt. This
					 * can happen if we receive the following,
					 *
					 *     execve->close->connect
					 *
					 * where the connect/close sequence is received
					 * OOO. So bounce the process from the remove list
					 * and continue. If the refcnt hits zero while we
					 * are here the channel will serialize it and we
					 * will handle normally. There is some risk that
					 * we skip 2 color bands if it just hit zero and
					 * then we run ticker event before the delete
					 * channel. We could use a bit of color to avoid
					 * later if we care. Also we may try to delete the
					 * process a second time, but that is harmless.
					 */
					ref := atomic.LoadUint32(&p.refcnt)
					if ref != 0 {
						continue
					}
					if p.color == deleteReady {
						p.color = deleted
						pc.remove(p.process)
					} else {
						newQueue = append(newQueue, p)
						p.color = deleteReady
					}
				}
				deleteQueue = newQueue
			case p := <-pc.deleteChan:
				// duplicate deletes can happen, if they do reset
				// color to pending and move along. This will cause
				// the GC to keep it alive for at least another pass.
				// Notice color is only ever touched inside GC behind
				// select channel logic so should be safe to work on
				// and assume its visible everywhere.
				if p.color != inUse {
					p.color = deletePending
					continue
				}
				// The object has already been deleted let if fall of
				// the edge of the world. Hitting this could mean our
				// GC logic deleted a process too early.
				// TBD add a counter around this to alert on it.
				if p.color == deleted {
					continue
				}
				p.color = deletePending
				deleteQueue = append(deleteQueue, p)
			}
		}
	}()
}

func (pc *Cache) deletePending(process *ProcessInternal) {
	pc.deleteChan <- process
}

func (pc *Cache) refDec(p *ProcessInternal, reason string) {
	p.refcntOpsLock.Lock()
	// count number of times refcnt is decremented for a specific reason (i.e. process, parent, etc.)
	p.refcntOps[reason]++
	p.refcntOpsLock.Unlock()
	ref := atomic.AddUint32(&p.refcnt, ^uint32(0))
	if ref == 0 {
		pc.deletePending(p)
	}
}

func (pc *Cache) refInc(p *ProcessInternal, reason string) {
	p.refcntOpsLock.Lock()
	// count number of times refcnt is increamented for a specific reason (i.e. process, parent, etc.)
	p.refcntOps[reason]++
	p.refcntOpsLock.Unlock()
	atomic.AddUint32(&p.refcnt, 1)
}

func (pc *Cache) purge() {
	pc.stopChan <- true
	processCacheTotal.Set(0)
}

func NewCache(
	processCacheSize int,
) (*Cache, error) {
	lruCache, err := lru.NewWithEvict(
		processCacheSize,
		func(_ string, _ *ProcessInternal) {
			processCacheEvictions.Inc()
		},
	)
	if err != nil {
		return nil, err
	}
	pm := &Cache{
		cache: lruCache,
		size:  processCacheSize,
	}
	pm.cacheGarbageCollector()
	return pm, nil
}

func (pc *Cache) get(processID string) (*ProcessInternal, error) {
	process, ok := pc.cache.Get(processID)
	if !ok {
		logger.GetLogger().WithField("id in event", processID).Debug("process not found in cache")
		processCacheMisses.WithLabelValues("get").Inc()
		return nil, fmt.Errorf("invalid entry for process ID: %s", processID)
	}
	return process, nil
}

// Add a ProcessInternal structure to the cache. Must be called only from
// clone or execve events
func (pc *Cache) add(process *ProcessInternal) bool {
	evicted := pc.cache.Add(process.process.ExecId, process)
	if !evicted {
		processCacheTotal.Inc()
	}
	return evicted
}

func (pc *Cache) remove(process *tetragon.Process) bool {
	present := pc.cache.Remove(process.ExecId)
	if present {
		processCacheTotal.Dec()
	} else {
		processCacheMisses.WithLabelValues("remove").Inc()
	}
	return present
}

func (pc *Cache) len() int {
	return pc.cache.Len()
}

func (pc *Cache) dump(opts *tetragon.DumpProcessCacheReqArgs) []*tetragon.ProcessInternal {
	var processes []*tetragon.ProcessInternal
	for _, v := range pc.cache.Values() {
		if opts.SkipZeroRefCnt && v.refcnt == 0 {
			continue
		}
		processes = append(processes, &tetragon.ProcessInternal{
			Process:   v.process,
			Refcnt:    &wrapperspb.UInt32Value{Value: v.refcnt},
			RefcntOps: v.refcntOps,
			Color:     colorStr[v.color],
		})
	}
	return processes
}
