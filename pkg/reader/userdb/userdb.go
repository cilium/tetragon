// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package userdb

import (
	"errors"
	"os/user"
	"strconv"
	"sync"
)

// Max system users ID is 999, usually maintained by distributions
// Reference: https://github.com/systemd/systemd/blob/main/docs/UIDS-GIDS.md#summary
const MaxSystemUserID = 999

// Errors
var (
	ErrNoEntry = errors.New("record does not exist")
)

type UsersDBCache struct {
	mu      sync.RWMutex
	records map[uint32]string
}

func newUsersCache() *UsersDBCache {
	return &UsersDBCache{
		records: make(map[uint32]string),
	}
}

var (
	UsersCache = newUsersCache()
)

func (cache *UsersDBCache) lookupUser(uid uint32) (string, error) {
	cache.mu.RLock()
	defer cache.mu.RUnlock()
	if name, ok := cache.records[uid]; ok {
		return name, nil
	}

	return "", ErrNoEntry
}

func (cache *UsersDBCache) addUser(uid uint32, username string) {
	cache.mu.Lock()
	cache.records[uid] = username
	cache.mu.Unlock()
}

func (cache *UsersDBCache) LookupUser(uid uint32) (string, error) {
	/* For now we just cache 0..MaxSystemUserID */
	if uid > MaxSystemUserID {
		// use Golang user.LookupId() as we want to only parse /etc/passwd for now
		userInfo, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
		if err != nil {
			return "", err
		}
		return userInfo.Name, nil
	}

	name, err := cache.lookupUser(uid)
	if err != nil {
		userInfo, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
		if err != nil {
			return "", err
		}
		name = userInfo.Name
		cache.addUser(uid, name)
	}
	return name, nil
}
