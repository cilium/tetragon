// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package process

import (
	"testing"

	"github.com/cilium/tetragon/api/v1/fgs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestProcessCache(t *testing.T) {
	// add a process to the cache.
	cache, err := NewCache(10)
	require.NoError(t, err)
	pid := wrapperspb.UInt32Value{Value: 1234}
	execID := "process1"
	proc := ProcessInternal{
		process: &fgs.Process{
			ExecId: execID,
			Pid:    &pid,
		},
		capabilities: &fgs.Capabilities{
			Permitted: []fgs.CapabilitiesType{
				fgs.CapabilitiesType_CAP_AUDIT_READ,
				fgs.CapabilitiesType_CAP_AUDIT_WRITE,
			},
		},
	}
	cache.Add(&proc)
	assert.Equal(t, cache.len(), 1)
	cache.AddToPidMap(pid.Value, execID)

	result, err := cache.get(proc.process.ExecId)
	assert.NoError(t, err)
	assert.Equal(t, proc.process.ExecId, result.process.ExecId)
	assert.Equal(t, proc.capabilities, result.capabilities)
	assert.Equal(t, cache.getFromPidMap(pid.Value), execID)

	// remove the entry from cache.
	assert.True(t, cache.remove(proc.process))
	assert.Equal(t, cache.len(), 0)
	assert.Equal(t, cache.pidMap.Len(), 0)
	_, err = cache.get(proc.process.ExecId)
	assert.Error(t, err)
	assert.Equal(t, cache.getFromPidMap(pid.Value), "")
}
