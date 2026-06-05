// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package process

import (
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/defaults"
)

func TestProcessCache(t *testing.T) {
	// add a process to the cache.
	cache, err := NewCache(10, defaults.DefaultProcessCacheGCInterval)
	require.NoError(t, err)
	defer cache.purge()
	pid := wrapperspb.UInt32Value{Value: 1234}
	execID := "process1"
	proc := ProcessInternal{
		process: &tetragon.Process{
			ExecId: execID,
			Pid:    &pid,
		},
		capabilities: &tetragon.Capabilities{
			Permitted: []tetragon.CapabilitiesType{
				tetragon.CapabilitiesType_CAP_AUDIT_READ,
				tetragon.CapabilitiesType_CAP_AUDIT_WRITE,
			},
		},
	}
	cache.add(&proc)
	assert.Equal(t, 1, cache.len())

	result, err := cache.get(proc.process.ExecId)
	require.NoError(t, err)
	assert.Equal(t, proc.process.ExecId, result.process.ExecId)
	assert.Equal(t, proc.capabilities, result.capabilities)

	// remove the entry from cache.
	assert.True(t, cache.remove(proc.process))
	assert.Equal(t, 0, cache.len())
	_, err = cache.get(proc.process.ExecId)
	require.Error(t, err)
}

func TestProcessCacheGCEarlyDeletion(t *testing.T) {
	cache, err := NewCache(10, 10*time.Millisecond)
	require.NoError(t, err)
	defer cache.purge()

	pid := wrapperspb.UInt32Value{Value: 1234}
	proc := ProcessInternal{
		process: &tetragon.Process{
			ExecId: "process1",
			Pid:    &pid,
		},
	}
	cache.add(&proc)

	proc.setColor(deleted)
	cache.deletePending(&proc)

	time.Sleep(50 * time.Millisecond)

	expected := strings.NewReader(`# HELP tetragon_process_cache_early_deletions_total Number of times the GC attempted to delete a process already marked as deleted. May indicate the GC is deleting processes too early.
# TYPE tetragon_process_cache_early_deletions_total counter
tetragon_process_cache_early_deletions_total 1
`)
	require.NoError(t, testutil.CollectAndCompare(processCacheEarlyDeletions, expected))
}

func TestProcessCacheGCLeak(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		interval := 10 * time.Millisecond
		cache, err := NewCache(10, interval)
		require.NoError(t, err)
		defer cache.purge()

		pid := wrapperspb.UInt32Value{Value: 1234}
		proc := ProcessInternal{
			process: &tetragon.Process{
				ExecId: "process1",
				Pid:    &pid,
			},
			refcntOps: make(map[string]int32),
		}
		proc.refcnt.Store(1)
		cache.add(&proc)

		// Trigger GC to see it, then increment refcnt while it's in the deleteQueue.
		// The GC should drop it from the queue and reset its color to inUse.
		cache.refDec(&proc, "test")
		synctest.Wait()
		assert.Equal(t, deletePending, proc.getColor())

		cache.refInc(&proc, "test")
		time.Sleep(interval + 1*time.Millisecond)
		synctest.Wait()
		assert.Equal(t, inUse, proc.getColor())

		// Trigger refDec to 0 again and wait for GC cycles to remove it.
		// Two GC cycles are needed because the GC moves processes from:
		// deletePending -> deleteReady in the first tick, and
		// deleteReady -> deleted in the second tick.
		cache.refDec(&proc, "test")
		synctest.Wait()

		time.Sleep(interval + 1*time.Millisecond)
		synctest.Wait()

		time.Sleep(interval + 1*time.Millisecond)
		synctest.Wait()

		assert.Equal(t, deleted, proc.getColor())
		assert.Equal(t, 0, cache.len())
	})
}

// TestProcessCacheColorDataRace exercises the GC goroutine writing the color
// field concurrently with another goroutine reading it via getEntries (the same
// read path used by dump). Before color was made atomic this test reports a data
// race under -race. It must stay clean now that color uses atomic access.
func TestProcessCacheColorDataRace(t *testing.T) {
	interval := 1 * time.Millisecond
	cache, err := NewCache(100, interval)
	require.NoError(t, err)
	defer cache.purge()

	procs := make([]*ProcessInternal, 0, 50)
	for i := 0; i < 50; i++ {
		p := &ProcessInternal{
			process: &tetragon.Process{
				ExecId: "proc" + strconv.Itoa(i),
				Pid:    &wrapperspb.UInt32Value{Value: uint32(1000 + i)},
			},
			refcntOps: make(map[string]int32),
		}
		p.refcnt.Store(1)
		cache.add(p)
		procs = append(procs, p)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Reader goroutine: reads color via the getEntries path repeatedly.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				cache.getEntries()
			}
		}
	}()

	// Writer goroutine: churns refcnt so the GC goroutine keeps writing color
	// (inUse -> deletePending -> deleteReady -> inUse ...).
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				for _, p := range procs {
					cache.refDec(p, "race")
					cache.refInc(p, "race")
				}
			}
		}
	}()

	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()
}

func TestProcessCacheDoubleParentDecrease(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		interval := 10 * time.Millisecond
		cache, err := NewCache(2, interval)
		require.NoError(t, err)
		defer cache.purge()

		parent := &ProcessInternal{
			process:   &tetragon.Process{ExecId: "parent", Pid: &wrapperspb.UInt32Value{Value: 100}},
			refcntOps: make(map[string]int32),
		}
		parent.refcnt.Store(1)
		cache.add(parent)

		child := &ProcessInternal{
			process:   &tetragon.Process{ExecId: "child", Pid: &wrapperspb.UInt32Value{Value: 101}, ParentExecId: "parent"},
			refcntOps: make(map[string]int32),
		}
		child.refcnt.Store(1)
		cache.add(child)

		cache.refInc(parent, "parent++")
		assert.Equal(t, uint32(2), parent.refcnt.Load())

		// simulate exit handler path
		if !child.GetParentRefcntDecreased() {
			parent.RefDec("parent")
			child.SetParentRefcntDecreased(true)
		}
		assert.Equal(t, uint32(1), parent.refcnt.Load())

		cache.refDec(child, "process--")
		synctest.Wait()
		assert.Equal(t, deletePending, child.getColor())

		// simulate resurrection: refInc after deletePending
		cache.refInc(child, "late-event")
		time.Sleep(interval + 1*time.Millisecond)
		synctest.Wait()
		assert.Equal(t, inUse, child.getColor())

		// trigger LRU eviction of child
		cache.get("parent")
		other := &ProcessInternal{
			process:   &tetragon.Process{ExecId: "other", Pid: &wrapperspb.UInt32Value{Value: 102}},
			refcntOps: make(map[string]int32),
		}
		other.refcnt.Store(1)
		cache.add(other)

		assert.Equal(t, uint32(1), parent.refcnt.Load())
	})
}
