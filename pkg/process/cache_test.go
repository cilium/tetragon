// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package process

import (
	"strings"
	"testing"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func createFakeProcess(pid uint32, execID string) *ProcessInternal {
	proc := ProcessInternal{
		process: &tetragon.Process{
			ExecId: execID,
			Pid:    &wrapperspb.UInt32Value{Value: pid},
		},
		capabilities: &tetragon.Capabilities{
			Permitted: []tetragon.CapabilitiesType{
				tetragon.CapabilitiesType_CAP_AUDIT_READ,
				tetragon.CapabilitiesType_CAP_AUDIT_WRITE,
			},
		},
		refcntOps: make(map[string]int32),
	}
	return &proc
}

func addFakeProcess(pc *Cache, pid uint32, execID string) {
	proc := createFakeProcess(pid, execID)
	pc.add(proc)
}

func TestProcessCacheAddAndRemove(t *testing.T) {
	// add a process to the cache.
	execId := "process1"
	cache, err := NewCache(10)
	require.NoError(t, err)
	addFakeProcess(cache, 1234, execId)
	assert.Equal(t, cache.len(), 1)

	result, err := cache.get(execId)
	assert.NoError(t, err)
	assert.Equal(t, execId, result.process.ExecId)
	assert.Equal(t, result.capabilities,
		&tetragon.Capabilities{
			Permitted: []tetragon.CapabilitiesType{
				tetragon.CapabilitiesType_CAP_AUDIT_READ,
				tetragon.CapabilitiesType_CAP_AUDIT_WRITE,
			},
		})

	// remove the entry from cache.
	assert.True(t, cache.remove(result.process))
	assert.Equal(t, cache.len(), 0)
	_, err = cache.get(execId)
	assert.Error(t, err)
}

func TestProcessCacheProcessOrChildExit(t *testing.T) {
	assert.True(t, processOrChildExit("process--"))
	assert.True(t, processOrChildExit("parent--"))
	assert.False(t, processOrChildExit("process++"))
	assert.False(t, processOrChildExit("parent++"))
	assert.False(t, processOrChildExit("process-x--"))
}

func TestProcessCacheProcessAndChildrenHaveExited(t *testing.T) {
	p := createFakeProcess(123, "myProc")
	// empty (invalid) process should be counted as exited (this situation shouldn't occur)
	assert.True(t, processAndChildrenHaveExited(p))
	p.refcntOps["process++"] = 1
	// active process has not exited
	assert.False(t, processAndChildrenHaveExited(p))
	p.refcntOps["process--"] = 1
	// completed process has exited
	assert.True(t, processAndChildrenHaveExited(p))
	// set the process as active again
	p.refcntOps["process--"] = 0
	p.refcntOps["parent++"] = 1
	// active process with child has not exited
	assert.False(t, processAndChildrenHaveExited(p))
	p.refcntOps["parent--"] = 1
	// active process with exited child has not exited
	assert.False(t, processAndChildrenHaveExited(p))
	p.refcntOps["process--"] = 1
	// completed process with exited child has exited
	assert.True(t, processAndChildrenHaveExited(p))
}

func TestProcessCacheRemoveStale(t *testing.T) {
	// add some processes to the cache.
	execId := []string{"process1", "process2", "process3", "process4", "process5", "process6", "process7"}
	var p []*ProcessInternal
	cache, err := NewCache(10)
	require.NoError(t, err)

	p = append(p, createFakeProcess(1234, execId[0]))
	p[0].refcntOps["process++"] = 1 // process started (but not exited)
	cache.add(p[0])
	assert.Equal(t, cache.len(), 1)

	p = append(p, createFakeProcess(1235, execId[1]))
	p[1].refcntOps["process++"] = 1                   // process started
	p[1].refcntOps["process--"] = 1                   // process exited
	p[1].exitTime = time.Now().Add(-20 * time.Minute) // exitTime is 20 minutes ago (stale)
	cache.add(p[1])
	assert.Equal(t, cache.len(), 2)

	p = append(p, createFakeProcess(1236, execId[2]))
	p[2].refcntOps["process++"] = 1                  // process started
	p[2].refcntOps["process--"] = 1                  // process exited
	p[2].exitTime = time.Now().Add(-2 * time.Minute) // exitTime is 2 minutes ago (not stale)
	cache.add(p[2])
	assert.Equal(t, cache.len(), 3)

	p = append(p, createFakeProcess(1237, execId[3]))
	p[3].refcntOps["process++"] = 1                   // process started
	p[3].refcntOps["process--"] = 1                   // process exited
	p[3].refcntOps["parent++"] = 1                    // child started
	p[3].exitTime = time.Now().Add(-20 * time.Minute) // exitTime is 20 minutes ago (but process is not stale)
	cache.add(p[3])
	assert.Equal(t, cache.len(), 4)

	p = append(p, createFakeProcess(1238, execId[4]))
	p[4].refcntOps["process++"] = 1                  // process started
	p[4].refcntOps["process--"] = 1                  // process exited
	p[4].refcntOps["parent++"] = 1                   // child started
	p[4].exitTime = time.Now().Add(-2 * time.Minute) // exitTime is 2 minutes ago (not stale)
	cache.add(p[4])
	assert.Equal(t, cache.len(), 5)

	p = append(p, createFakeProcess(1239, execId[5]))
	p[5].refcntOps["process++"] = 1                   // process started
	p[5].refcntOps["process--"] = 1                   // process exited
	p[5].refcntOps["parent++"] = 1                    // child started
	p[5].refcntOps["parent--"] = 1                    // child exited
	p[5].exitTime = time.Now().Add(-20 * time.Minute) // exitTime is 20 minutes ago (stale)
	cache.add(p[5])
	assert.Equal(t, cache.len(), 6)

	p = append(p, createFakeProcess(1240, execId[6]))
	p[6].refcntOps["process++"] = 1                  // process started
	p[6].refcntOps["process--"] = 1                  // process exited
	p[6].refcntOps["parent++"] = 1                   // child started
	p[6].refcntOps["parent--"] = 1                   // child exited
	p[6].exitTime = time.Now().Add(-2 * time.Minute) // exitTime is 2 minutes ago (not stale)
	cache.add(p[6])
	assert.Equal(t, cache.len(), 7)

	// confirm entries are in cache
	for i := 0; i < 7; i++ {
		result, err := cache.get(execId[i])
		assert.NoError(t, err)
		assert.Equal(t, execId[i], result.process.ExecId)
	}

	// remove stale entries from cache.
	cache.cleanStaleEntries()

	// two entries should have been removed
	assert.Equal(t, cache.len(), 5)
	assert.NoError(t, testutil.CollectAndCompare(processCacheRemovedStale, strings.NewReader(`# HELP tetragon_process_cache_removed_stale_total Number of process cache stale entries removed.
# TYPE tetragon_process_cache_removed_stale_total counter
tetragon_process_cache_removed_stale_total 2
`)))

	// confirm entries are in cache
	for i := 0; i < 7; i++ {
		result, err := cache.get(execId[i])
		switch i {
		case 0, 2, 3, 4, 6:
			assert.NoError(t, err)
			assert.Equal(t, execId[i], result.process.ExecId)
		case 1, 5:
			assert.Error(t, err)
		}
	}
}
