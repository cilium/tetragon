// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package bpf

import (
	"errors"
	"fmt"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/selectors"
	"github.com/cilium/tetragon/pkg/sensors/exec/execvemap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const programNamePidMatch = "test_pid_match"

type testContext struct {
	coll     *ebpf.Collection
	prog     *ebpf.Program
	execvMap *ebpf.Map
}

// setupTest loads the test program and returns a test context.
func setupTest(t *testing.T) (*testContext, error) {
	ctx := &testContext{}
	// load test program
	coll, err := ebpf.LoadCollection("objs/pid_match_test.o")
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("verifier error: %+v", ve)
		}
		return nil, err
	}
	ctx.coll = coll

	var ok bool
	ctx.prog, ok = coll.Programs[programNamePidMatch]
	require.True(t, ok, "program %s not found", programNamePidMatch)

	ctx.execvMap, ok = coll.Maps["execve_map"]
	require.True(t, ok, "execve_map not found")

	return ctx, nil
}

func (ctx *testContext) cleanup() {
	if ctx.coll != nil {
		ctx.coll.Close()
	}
}

// runProg runs the test program with the given PID and returns the result.
func (ctx *testContext) runProg(selfPid uint32) (uint32, error) {
	err := ctx.execvMap.Update(uint32(0), &execvemap.ExecveValue{
		Process: processapi.MsgExecveKey{Pid: selfPid},
	}, 0)
	if err != nil {
		return 0, fmt.Errorf("failed to update execve map: %w", err)
	}
	res, err := ctx.prog.Run(&ebpf.RunOptions{})
	if err != nil {
		return 0, fmt.Errorf("failed to run program: %w", err)
	}
	return res, nil
}

// initKernelStateData initializes the kernel state data with the given PIDs.
func (ctx *testContext) initKernelStateData(pids []uint32) error {
	k := &selectors.KernelSelectorState{}
	err := selectors.ParseMatchPid(k, &v1alpha1.PIDSelector{
		Operator:       "In",
		Values:         pids,
		IsNamespacePID: false,
		FollowForks:    false,
	})
	if err != nil {
		return fmt.Errorf("failed to parse PID selector: %w", err)
	}

	filterMap, ok := ctx.coll.Maps["test_filter_map"]
	if !ok {
		return errors.New("test_filter_map not found")
	}

	return filterMap.Update(uint32(0), k.Buffer(), 0)
}

func Test_PidMatch(t *testing.T) {
	ctx, err := setupTest(t)
	require.NoError(t, err)
	defer ctx.cleanup()

	tests := []struct {
		name     string
		pids     []uint32
		testPid  uint32
		expected uint32
	}{
		// Test case where the test PID is the only PID to match.
		{
			name:     "Match_1_PID",
			pids:     []uint32{1},
			testPid:  1,
			expected: 1,
		},
		// Test case where the test PID is in the list of 2 PIDs to match.
		{
			name:     "Match_2_PID",
			pids:     []uint32{1, 2},
			testPid:  2,
			expected: 1,
		},
		// Test case where the test PID is not in the list of 2 PIDs to match.
		{
			name:     "Match_2_PID_NOT_IN_LIST",
			pids:     []uint32{1, 2},
			testPid:  3,
			expected: 0,
		},
		// Test case where the test PID is in the list of 4 PIDs to match.
		{
			name:     "Match_4_PID",
			pids:     []uint32{1, 2, 3, 4},
			testPid:  4,
			expected: 1,
		},
		// Test case where the test PID is not in the list of 4 PIDs to match.
		{
			name:     "Match_4_PID_NOT_IN_LIST",
			pids:     []uint32{1, 2, 3, 4},
			testPid:  5,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.NoError(t, ctx.initKernelStateData(tt.pids))
			result, err := ctx.runProg(tt.testPid)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}
