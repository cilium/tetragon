// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows && !nok8s

package cgidmap

import (
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/metrics"
)

func mkIDs(n int) []unmappedID {
	ret := make([]unmappedID, 0, n)
	for range n {
		ret = append(ret, unmappedID{podID: uuid.New(), contID: ContainerID(uuid.New().String())})
	}
	return ret
}

// fakeMap records Add calls so resolve() can be exercised without a real cgidmap.
type fakeMap struct {
	mu    sync.Mutex
	added []unmappedID
	cgIDs []CgroupID
}

func (f *fakeMap) Get(CgroupID) (ContainerID, bool) { return "", false }
func (f *fakeMap) Update(PodID, []ContainerID)      {}
func (f *fakeMap) Add(podID PodID, contID ContainerID, cgID CgroupID) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.added = append(f.added, unmappedID{podID: podID, contID: contID})
	f.cgIDs = append(f.cgIDs, cgID)
}

// addedIDs returns a snapshot of the recorded Add calls, safe to call while a
// resolver worker is running.
func (f *fakeMap) addedIDs() []unmappedID {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.added)
}

func TestResolve(t *testing.T) {
	id := unmappedID{podID: uuid.New(), contID: "cont-abc"}

	t.Run("adds resolved cgroup id", func(t *testing.T) {
		fm := &fakeMap{}
		r := &resolver{
			m:                fm,
			containerPath:    func(unmappedID) (string, error) { return "/sys/fs/cgroup/pod/cont", nil },
			getCgroupID:      func(string) (uint64, error) { return 4242, nil },
			addCgTrackerPath: func(string) error { return nil },
		}
		require.NoError(t, r.resolve(id))
		require.Equal(t, []unmappedID{id}, fm.added)
		require.Equal(t, []CgroupID{4242}, fm.cgIDs)
	})

	t.Run("containerPath error short-circuits before Add", func(t *testing.T) {
		wantErr := errors.New("no path")
		fm := &fakeMap{}
		r := &resolver{
			m:                fm,
			containerPath:    func(unmappedID) (string, error) { return "", wantErr },
			getCgroupID:      func(string) (uint64, error) { return 4242, nil },
			addCgTrackerPath: func(string) error { return nil },
		}
		require.ErrorIs(t, r.resolve(id), wantErr)
		require.Empty(t, fm.added)
	})

	t.Run("getCgroupID error short-circuits before Add", func(t *testing.T) {
		wantErr := errors.New("bad cgroup path")
		fm := &fakeMap{}
		r := &resolver{
			m:                fm,
			containerPath:    func(unmappedID) (string, error) { return "/some/path", nil },
			getCgroupID:      func(string) (uint64, error) { return 0, wantErr },
			addCgTrackerPath: func(string) error { return nil },
		}
		require.ErrorIs(t, r.resolve(id), wantErr)
		require.Empty(t, fm.added)
	})
}

// testCounter returns a throwaway counter so tests do not touch the global
// metric state.
func testCounter(name string) *metrics.Counter {
	return metrics.MustNewCounter(
		metrics.NewOpts("test", "cgidmap", name, name, nil, nil, nil), nil)
}

func TestResolverWorker(t *testing.T) {
	fm := &fakeMap{}
	r := newResolver(fm, func(id unmappedID) (string, error) { return "/sys/fs/cgroup/pod/" + id.contID, nil },
		func(string) error { return nil },
		testCounter("resolutions_total"), testCounter("resolution_errors_total"))
	// avoid touching the real filesystem; the worker only reads this after
	// dequeueing, so setting it before enqueue is safe.
	r.getCgroupID = func(string) (uint64, error) { return 4242, nil }

	ids := mkIDs(2)
	r.enqueue(ids)
	require.Eventually(t, func() bool { return len(fm.addedIDs()) == len(ids) },
		5*time.Second, 10*time.Millisecond)
	require.ElementsMatch(t, ids, fm.addedIDs())
}
