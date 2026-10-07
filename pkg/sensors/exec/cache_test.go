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
	require.NoError(t, cmd.Start())
	pid := uint32(cmd.Process.Pid)
	require.NoError(t, cmd.Wait())

	inCache := func() bool {
		processes := process.DumpProcessCache(&tetragon.DumpProcessCacheReqArgs{SkipZeroRefcnt: false, ExcludeExecveMapProcesses: false})
		return processInList(pid, processes)
	}

	require.Eventually(t, inCache, 5*time.Second, 10*time.Millisecond)

	// The process should be evicted shortly after. Normally this takes 100-200ms,
	// but on kernels without the BPF ring buffer (< 5.11) the exit event may be
	// read before the exec event, in which case it is only reprocessed after the
	// event cache retry delay (2s). The bound is well below the default GC
	// interval (30s), so this still verifies that the configured interval is used.
	require.Eventually(t, func() bool { return !inCache() }, 10*time.Second, 50*time.Millisecond)
}
