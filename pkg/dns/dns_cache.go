// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package dns

import (
	"fmt"

	lru "github.com/hashicorp/golang-lru"
)

var (
	LazyDns             = false
	dnsDefaultCacheSize = 1024
)

type Cache struct {
	cache *lru.Cache
}

func NewCache() (*Cache, error) {
	lru, err := lru.New(dnsDefaultCacheSize)
	if err != nil {
		return nil, err
	}
	return &Cache{
		cache: lru,
	}, nil
}

func (c *Cache) GetIp(ip string) ([]string, error) {
	entry, ok := c.cache.Get(ip)
	if !ok {
		return nil, fmt.Errorf("no dns entry found")
	}
	return entry.([]string), nil
}

func (c *Cache) AddIp(ips, names []string) {
	for _, ip := range ips {
		c.cache.Add(ip, names)
	}
}

func CiliumDnsEnabled() bool {
	return LazyDns
}
