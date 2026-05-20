// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package program

import (
	"os"
	"path/filepath"
	"sync"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
)

var sharedPinnedMaps = struct {
	mu   sync.Mutex
	refs map[string]int
}{
	refs: make(map[string]int),
}

func acquireSharedPinnedMap(pinPath string) {
	if pinPath == "" {
		return
	}

	sharedPinnedMaps.mu.Lock()
	defer sharedPinnedMaps.mu.Unlock()
	sharedPinnedMaps.refs[pinPath]++
}

func releaseSharedPinnedMaps(pinPaths []string, unpin bool) {
	if !unpin {
		return
	}
	for _, pinPath := range pinPaths {
		releaseSharedPinnedMap(pinPath)
	}
}

func releaseSharedPinnedMap(pinPath string) {
	if pinPath == "" {
		return
	}

	sharedPinnedMaps.mu.Lock()
	defer sharedPinnedMaps.mu.Unlock()

	refs := sharedPinnedMaps.refs[pinPath]
	if refs > 1 {
		sharedPinnedMaps.refs[pinPath] = refs - 1
		return
	}
	delete(sharedPinnedMaps.refs, pinPath)

	if err := os.Remove(pinPath); err != nil && !os.IsNotExist(err) {
		logger.GetLogger().Warn("Failed to unpin shared map", "map", pinPath, logfields.Error, err)
	}

	// These directories are content-addressed and only hold the shared map.
	// Remove succeeds only when they are empty.
	_ = os.Remove(filepath.Dir(pinPath))
	_ = os.Remove(filepath.Dir(filepath.Dir(pinPath)))
}
