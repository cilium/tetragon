// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package exec

import (
	"context"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/process"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func processInList(pid uint32, processes []*tetragon.ProcessInternal) bool {
	for _, p := range processes {
		if p.Process.Pid.Value == pid {
			return true
		}
	}
	return false
}

func TestProcessCacheInterval(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	sleepBin := "/bin/sleep"

	obs, err := observertesthelper.GetDefaultObserver(t, ctx, tus.Conf().TetragonLib, observertesthelper.WithProcCacheGCInterval(100*time.Millisecond))
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	cmd := exec.Command(sleepBin, "0.001")
	assert.NoError(t, cmd.Start())
	pid := cmd.Process.Pid
	time.Sleep(50 * time.Millisecond)

	processes := process.DumpProcessCache(&tetragon.DumpProcessCacheReqArgs{SkipZeroRefcnt: false, ExcludeExecveMapProcesses: false})
	// Should find our sleep process in the list, even though the process should have finished.
	require.True(t, processInList(uint32(pid), processes))

	time.Sleep(500 * time.Millisecond)
	processes = process.DumpProcessCache(&tetragon.DumpProcessCacheReqArgs{SkipZeroRefcnt: false, ExcludeExecveMapProcesses: false})
	// Should not find our sleep process in the list, as it should have been evicted by now.
	require.False(t, processInList(uint32(pid), processes))
}
