// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metrics

import (
	"sync"
	"sync/atomic"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	binaryCache atomic.Pointer[lru.Cache[string, struct{}]]

	evictedBinaries     []string
	evictedBinariesLock sync.Mutex
	evictedWake         = make(chan struct{}, 1)
	deleterOnce         sync.Once
	binaryLock          sync.Mutex
)

// InitBinaryCache bounds the number of distinct "binary" label values kept in
// the process metrics to size. Above the bound, the least recently seen binary
// is evicted and its series are deleted from the metrics registered with the
// *WithPod constructors. A size of 0 disables the bound.
func InitBinaryCache(size int) error {
	if size == 0 {
		binaryCache.Store(nil)
		return nil
	}
	cache, err := lru.NewWithEvict(size, func(binary string, _ struct{}) {
		queueBinaryDelete(binary)
	})
	if err != nil {
		return err
	}
	binaryCache.Store(cache)
	deleterOnce.Do(func() { go deleteEvictedBinaries() })
	return nil
}

// TrackBinary records that binary was used as a label value.
func TrackBinary(binary string) {
	if binary == "" {
		return
	}
	if cache := binaryCache.Load(); cache != nil {
		binaryLock.Lock()
		cache.Add(binary, struct{}{})
		binaryLock.Unlock()
	}
}

// queueBinaryDelete runs on the event processing path, inside the cache's
// lock, so it only records the eviction. Deleting the series scans every
// registered metric and is left to deleteEvictedBinaries.
func queueBinaryDelete(binary string) {
	evictedBinariesLock.Lock()
	evictedBinaries = append(evictedBinaries, binary)
	evictedBinariesLock.Unlock()
	select {
	case evictedWake <- struct{}{}:
	default:
	}
}

func deleteEvictedBinaries() {
	for range evictedWake {
		evictedBinariesLock.Lock()
		batch := evictedBinaries
		evictedBinaries = nil
		evictedBinariesLock.Unlock()
		for _, binary := range batch {
			deleteBinary(binary)
		}
	}
}

func deleteBinary(binary string) {
	binaryLock.Lock()
	defer binaryLock.Unlock()
	// Seen again since the eviction: keep its series.
	if cache := binaryCache.Load(); cache != nil && cache.Contains(binary) {
		return
	}
	labels := prometheus.Labels{"binary": binary}
	for _, metric := range ListMetricsWithPod() {
		metric.DeletePartialMatch(labels)
	}
}
