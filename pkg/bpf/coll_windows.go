//go:build windows

package bpf

import (
	"errors"
	"sync"

	"github.com/cilium/ebpf"
)

type CollectionStore struct {
	collMap map[string]*ebpf.Collection
}

var (
	store          CollectionStore
	collstoreMutex sync.RWMutex
)

func SetCollection(name string, coll *ebpf.Collection) {
	collstoreMutex.Lock()
	store.collMap[name] = coll
	collstoreMutex.Unlock()
}

func GetCollection(name string) (*ebpf.Collection, error) {
	collstoreMutex.RLock()
	coll, ok := store.collMap[name]
	collstoreMutex.RUnlock()
	if ok {
		return coll, nil
	}
	return nil, errors.New("collection object not found")
}

func init() {
	store.collMap = make(map[string]*ebpf.Collection)
}
