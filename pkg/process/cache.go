// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package process

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics/errormetrics"
	"github.com/cilium/tetragon/pkg/metrics/mapmetrics"
	lru "github.com/hashicorp/golang-lru/v2"
)

type CacheId struct {
	pid      uint32
	ktime    uint64
	nodeName string
}

type Cache struct {
	cache      *lru.Cache[CacheId, *ProcessInternal]
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
						pc.remove(p.cacheId)
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

func (pc *Cache) refDec(p *ProcessInternal) {
	ref := atomic.AddUint32(&p.refcnt, ^uint32(0))
	if ref == 0 {
		pc.deletePending(p)
	}
}

func (pc *Cache) refInc(p *ProcessInternal) {
	atomic.AddUint32(&p.refcnt, 1)
}

func (pc *Cache) Purge() {
	pc.stopChan <- true
}

func NewCache(
	processCacheSize int,
) (*Cache, error) {
	lruCache, err := lru.NewWithEvict(
		processCacheSize,
		func(_ CacheId, _ *ProcessInternal) {
			mapmetrics.MapDropInc("processLru")
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

func (pc *Cache) get(processID CacheId) (*ProcessInternal, error) {
	process, ok := pc.cache.Get(processID)
	if !ok {
		logger.GetLogger().WithField("id in event", processID).Debug("process not found in cache")
		errormetrics.ErrorTotalInc(errormetrics.ProcessCacheMissOnGet)
		return nil, fmt.Errorf("invalid entry for process ID: %v", processID)
	}
	return process, nil
}

// Add a ProcessInternal structure to the cache. Must be called only from
// clone or execve events
func (pc *Cache) add(cacheId CacheId, process *ProcessInternal) bool {
	evicted := pc.cache.Add(cacheId, process)
	if evicted {
		errormetrics.ErrorTotalInc(errormetrics.ProcessCacheEvicted)
	}
	return evicted
}

func (pc *Cache) remove(cacheId CacheId) bool {
	present := pc.cache.Remove(cacheId)
	if !present {
		errormetrics.ErrorTotalInc(errormetrics.ProcessCacheMissOnRemove)
	}
	return present
}

func (pc *Cache) len() int {
	return pc.cache.Len()
}
