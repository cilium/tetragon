// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package program

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"
)

func TestSharedMapConcurrent(t *testing.T) {
	dir, err := os.MkdirTemp("/sys/fs/bpf", "tetragon-map-test-")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	pinPath := filepath.Join(dir, "test_map")
	spec := &ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1}

	maps := make([]*Map, 16)
	for i := range maps {
		maps[i] = MapShared("test_map")
		maps[i].PinPath = pinPath
	}
	forEach := func(fn func(*Map) error) error {
		errs := make([]error, len(maps))
		var wg sync.WaitGroup
		for i, m := range maps {
			wg.Go(func() { errs[i] = fn(m) })
		}
		wg.Wait()
		return errors.Join(errs...)
	}

	require.NoError(t, forEach(func(m *Map) error { return m.LoadOrCreatePinnedMap(pinPath, spec) }))
	require.Equal(t, len(maps), sharedMapRefs[pinPath])
	require.FileExists(t, pinPath)

	require.NoError(t, forEach(func(m *Map) error { return m.Unload(true) }))
	require.NotContains(t, sharedMapRefs, pinPath)
	require.NoFileExists(t, pinPath)
}
