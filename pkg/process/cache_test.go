// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package process

import (
	"strings"
	"testing"
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

	proc.color = deleted
	cache.deletePending(&proc)

	time.Sleep(50 * time.Millisecond)

	expected := strings.NewReader(`# HELP tetragon_process_cache_early_deletions_total Number of times the GC attempted to delete a process already marked as deleted. May indicate the GC is deleting processes too early.
# TYPE tetragon_process_cache_early_deletions_total counter
tetragon_process_cache_early_deletions_total 1
`)
	require.NoError(t, testutil.CollectAndCompare(processCacheEarlyDeletions, expected))
}
