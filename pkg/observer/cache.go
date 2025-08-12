// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package observer

import (
	"fmt"

	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/cilium/tetragon/pkg/api/dataapi"
)

type cache struct {
	cache *lru.Cache[dataapi.DataEventId, []byte]
	size  int
}

// newCache constructs a cache of fixed size with the callback function that increments
// data_cache_evictions_total counter every time the cache is evicted.
func newCache(dataCacheSize int) (*cache, error) {
	lruCache, err := lru.NewWithEvict(
		dataCacheSize,
		func(_ dataapi.DataEventId, _ []byte) {
			dataCacheEvictions.Inc()
		},
	)
	if err != nil {
		return nil, err
	}
	cache := &cache{
		cache: lruCache,
		size:  dataCacheSize,
	}
	return cache, nil
}

func (c *cache) get(dataEventId dataapi.DataEventId) ([]byte, error) {
	data, ok := c.cache.Get(dataEventId)
	if !ok {
		dataCacheMisses.WithLabelValues("get").Inc()
		return nil, fmt.Errorf("data event with id : %v not found", dataEventId)
	}
	return data, nil
}

func (c *cache) add(id dataapi.DataEventId, msgData []byte) bool {
	evicted := c.cache.Add(id, msgData)
	if !evicted {
		dataCacheTotal.Inc()
	}
	return evicted
}

func (c *cache) remove(desc dataapi.DataEventDesc) bool {
	present := c.cache.Remove(desc.Id)
	if present {
		dataCacheTotal.Dec()
	} else {
		dataCacheMisses.WithLabelValues("remove").Inc()
	}
	return present
}
