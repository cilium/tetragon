// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package process

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics/errormetrics"
	"github.com/cilium/tetragon/pkg/metrics/mapmetrics"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/proc"
	"github.com/cilium/tetragon/pkg/sensors/base"
	"github.com/cilium/tetragon/pkg/sensors/exec/execvemap"
	lru "github.com/hashicorp/golang-lru/v2"
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
	if val, ok := p.refcntOps[reason]; ok {
		p.refcntOps[reason] = val + 1
	} else {
		p.refcntOps[reason] = 1
	}
	p.refcntOpsLock.Unlock()
	ref := atomic.AddUint32(&p.refcnt, ^uint32(0))
	if ref == 0 {
		pc.deletePending(p)
	}
}

func (pc *Cache) refInc(p *ProcessInternal, reason string) {
	p.refcntOpsLock.Lock()
	if val, ok := p.refcntOps[reason]; ok {
		p.refcntOps[reason] = val + 1
	} else {
		p.refcntOps[reason] = 1
	}
	p.refcntOpsLock.Unlock()
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
		func(_ string, _ *ProcessInternal) {
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

func (pc *Cache) get(processID string) (*ProcessInternal, error) {
	process, ok := pc.cache.Get(processID)
	if !ok {
		logger.GetLogger().WithField("id in event", processID).Debug("process not found in cache")
		errormetrics.ErrorTotalInc(errormetrics.ProcessCacheMissOnGet)
		return nil, fmt.Errorf("invalid entry for process ID: %s", processID)
	}
	return process, nil
}

// Add a ProcessInternal structure to the cache. Must be called only from
// clone or execve events
func (pc *Cache) add(process *ProcessInternal) bool {
	evicted := pc.cache.Add(process.process.ExecId, process)
	if evicted {
		errormetrics.ErrorTotalInc(errormetrics.ProcessCacheEvicted)
	}
	return evicted
}

func (pc *Cache) remove(process *tetragon.Process) bool {
	present := pc.cache.Remove(process.ExecId)
	if !present {
		errormetrics.ErrorTotalInc(errormetrics.ProcessCacheMissOnRemove)
	}
	return present
}

func (pc *Cache) len() int {
	return pc.cache.Len()
}

func (pc *Cache) Dump(skipZeroRefCnt bool) {
	fmt.Printf("\n\n")
	pl := pc.cache.Values()
	processLRUSet := make(map[uint32]bool)
	for _, v := range pl {
		processLRUSet[v.process.Pid.Value] = true
	}
	processLRULen := len(pl)

	mapFname := filepath.Join(defaults.DefaultMapRoot, defaults.DefaultMapPrefix, base.ExecveMap.Name)
	m, err := ebpf.LoadPinnedMap(mapFname, &ebpf.LoadPinOptions{
		ReadOnly: true,
	})
	if err != nil {
		logger.GetLogger().WithError(err).Fatal("failed to open execve map")
		return
	}
	defer m.Close()

	data := make(map[execvemap.ExecveKey]execvemap.ExecveValue)
	iter := m.Iterate()

	var key execvemap.ExecveKey
	var val execvemap.ExecveValue
	for iter.Next(&key, &val) {
		data[key] = val
	}

	if err := iter.Err(); err != nil {
		logger.GetLogger().WithError(err).Fatal("error iterating execve map")
	}

	execveMapSet := make(map[uint32]bool)
	for k := range data {
		execveMapSet[k.Pid] = true
	}
	execveMapLen := len(data)

	fmt.Printf("************ items in processLRU (%d) but not in execve_map (%d) ************\n", processLRULen, execveMapLen)
	for _, v := range pl {
		exists := execveMapSet[v.process.Pid.Value]
		if !exists {
			if skipZeroRefCnt && v.refcnt == 0 {
				continue
			}
			v.refcntOpsLock.Lock()
			opsStr := fmt.Sprint(v.refcntOps)
			v.refcntOpsLock.Unlock()
			fmt.Println(v.process.Pid.GetValue(), "|", v.process.ExecId, "|", v.process.ParentExecId, "|", v.process.Binary, v.process.Arguments, "|", v.process.Flags, "|", v.refcnt, v.color, opsStr)
		}
	}

	fmt.Printf("************ items in execve_map (%d) but not in processLRU (%d) *************\n", execveMapLen, processLRULen)
	for k := range data {
		exists := processLRUSet[k.Pid]
		if !exists {
			fmt.Println(k.Pid)
		}
	}

	procFS, err := os.ReadDir(option.Config.ProcFS)
	if err != nil {
		return
	}

	procSet := make(map[uint32]bool)
	for _, d := range procFS {
		if !d.IsDir() {
			continue
		}

		if !regexp.MustCompile(`\d`).MatchString(d.Name()) {
			continue
		}

		pathName := filepath.Join(option.Config.ProcFS, d.Name())

		cmdline, err := os.ReadFile(filepath.Join(pathName, "cmdline"))
		if err != nil {
			continue
		}

		kernelThread := false
		if string(cmdline) == "" {
			kernelThread = true
		}

		status, err := proc.GetStatus(pathName)
		if err != nil {
			continue
		}

		// check and add only tgid processes
		if len(status.NSpid) > 0 && len(status.NStgid) > 0 {
			nspid, errNSpid := strconv.ParseUint(status.NSpid[0], 10, 32)
			nstgid, errNStgid := strconv.ParseUint(status.NStgid[0], 10, 32)
			if !kernelThread && errNSpid == nil && errNStgid == nil && nspid != nstgid {
				continue
			}
		}

		name := d.Name()
		s, err := strconv.ParseUint(name, 10, 32)
		if err != nil {
			fmt.Println("Skipping:", name)
			continue
		}

		procSet[uint32(s)] = true
	}
	procSetLen := len(procSet)

	fmt.Printf("************ items in execve_map (%d) but not in proc (%d) *************\n", execveMapLen, procSetLen)
	for k := range data {
		exists := procSet[k.Pid]
		if !exists {
			if k.Pid != 0 { // we know that we have an entry with 0
				fmt.Println(k.Pid)
			}
		}
	}

	fmt.Printf("************ items in proc (%d)  but not in execve_map (%d)  *************\n", procSetLen, execveMapLen)
	for k := range procSet {
		_, exists := data[execvemap.ExecveKey{Pid: k}]
		if !exists {
			fmt.Println(k)
		}
	}

	fmt.Println("******************************************************************************")
	fmt.Printf("\n\n")
}
