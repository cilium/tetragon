// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package exec

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
)

const joinedInfoMapName = "tg_execve_joined_info_map"

type joinedInfoMapMetrics struct {
	entries, capacity, errorsUpdate, errorsDelete float64
}

// readJoinedInfoMapMetrics gathers the BPF map metrics and returns the
// tg_execve_joined_info_map ones.
// See pkg/metrics/mapmetrics/mapmetrics.go.
func readJoinedInfoMapMetrics(t *testing.T) joinedInfoMapMetrics {
	reg := prometheus.NewRegistry()
	require.NoError(t, reg.Register(observer.NewBPFCollector()))
	families, err := reg.Gather()
	require.NoError(t, err)

	var ret joinedInfoMapMetrics
	found := map[string]bool{}
	for _, family := range families {
		for _, metric := range family.GetMetric() {
			isJoinedInfo := false
			for _, label := range metric.GetLabel() {
				if label.GetName() == "map" && label.GetValue() == joinedInfoMapName {
					isJoinedInfo = true
					break
				}
			}
			if !isJoinedInfo {
				continue
			}
			val := metric.GetGauge().GetValue()
			switch family.GetName() {
			case "tetragon_map_entries":
				ret.entries = val
			case "tetragon_map_capacity":
				ret.capacity = val
			case "tetragon_map_errors_update_total":
				ret.errorsUpdate = val
			case "tetragon_map_errors_delete_total":
				ret.errorsDelete = val
			default:
				continue
			}
			found[family.GetName()] = true
		}
	}
	require.Len(t, found, 4, "missing %s metrics, got: %v", joinedInfoMapName, found)
	return ret
}

// execMemfdTrue runs /bin/true from a memfd, which has no links and therefore
// gets an entry in tg_execve_joined_info_map at exec time. It returns the exec
// path and inode number.
func execMemfdTrue(t *testing.T, arg string) (string, uint64) {
	fd, err := unix.MemfdCreate(arg, 0)
	require.NoError(t, err)

	execPath := fmt.Sprintf("/proc/self/fd/%d", fd)
	file := os.NewFile(uintptr(fd), execPath)
	defer file.Close()

	binData, err := os.ReadFile("/bin/true")
	require.NoError(t, err)
	_, err = file.Write(binData)
	require.NoError(t, err)

	var stat syscall.Stat_t
	require.NoError(t, syscall.Stat(execPath, &stat))

	require.NoError(t, exec.Command(execPath, arg).Run())
	return execPath, stat.Ino
}

// TestExecveJoinedInfoMapMetrics checks that entries added to
// tg_execve_joined_info_map by security_bprm_committing_creds are consumed
// and released by the execve event, and that this is reflected in the map
// metrics.
func TestExecveJoinedInfoMapMetrics(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	obs, err := observertesthelper.GetDefaultObserver(t, ctx, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	require.NoError(t, err)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	before := readJoinedInfoMapMetrics(t)

	expectedCapacity := float64(8192)
	if config.EnableV61Progs() || config.EnableV511Progs() {
		// Task storage maps have no max entries.
		expectedCapacity = 0
	}
	require.InDelta(t, expectedCapacity, before.capacity, 0)

	const execs = 16
	var checkers []ec.EventChecker
	for i := range execs {
		arg := fmt.Sprintf("tetragon-test-joined-info-%d", i)
		execPath, ino := execMemfdTrue(t, arg)
		checkers = append(checkers, ec.NewProcessExecChecker(arg).
			WithProcess(ec.NewProcessChecker().
				WithBinary(sm.Suffix(execPath)).
				WithArguments(sm.Full(arg)).
				WithBinaryProperties(ec.NewBinaryPropertiesChecker().
					WithFile(ec.NewFilePropertiesChecker().
						WithInode(ec.NewInodePropertiesChecker().
							WithLinks(0).
							WithNumber(ino),
						),
					),
				),
			))
	}

	// The inode information in the events can only come from the joined
	// info map, so this proves the entries were set and read.
	require.NoError(t, jsonchecker.JsonTestCheck(t, ec.NewUnorderedEventChecker(checkers...)))

	// Every entry must have been deleted by the execve event. Other
	// processes on the host may exec privileged binaries concurrently, so
	// allow some time to settle back to the baseline.
	require.Eventually(t, func() bool {
		return readJoinedInfoMapMetrics(t).entries == before.entries
	}, 5*time.Second, 100*time.Millisecond, "%s entries did not return to %v", joinedInfoMapName, before.entries)

	after := readJoinedInfoMapMetrics(t)
	require.InDelta(t, before.errorsUpdate, after.errorsUpdate, 0, "unexpected update errors")
	require.InDelta(t, before.errorsDelete, after.errorsDelete, 0, "unexpected delete errors")
	require.InDelta(t, before.capacity, after.capacity, 0)
}
