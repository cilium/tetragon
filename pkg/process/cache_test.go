// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package process

import (
	"testing"

	"github.com/cilium/tetragon/api/v1/tetragon"
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
		process_: &tetragon.Process{
			ExecId: execID,
			Pid:    &pid,
		},
		capabilities_: &tetragon.Capabilities{
			Permitted: []tetragon.CapabilitiesType{
				tetragon.CapabilitiesType_CAP_AUDIT_READ,
				tetragon.CapabilitiesType_CAP_AUDIT_WRITE,
			},
		},
	}
	cache.add(&proc)
	assert.Equal(t, cache.len(), 1)

	result, err := cache.get(proc.process_.ExecId)
	assert.NoError(t, err)
	assert.Equal(t, proc.process_.ExecId, result.process_.ExecId)
	assert.Equal(t, proc.capabilities_, result.capabilities_)

	// remove the entry from cache.
	assert.True(t, cache.remove(proc.process_))
	assert.Equal(t, cache.len(), 0)
	_, err = cache.get(proc.process_.ExecId)
	assert.Error(t, err)
}
