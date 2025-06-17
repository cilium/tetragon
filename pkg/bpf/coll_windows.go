//go:build windows

package bpf

import (
	"errors"
	"sync"

	"github.com/cilium/ebpf"
)

var (
	collectionByName map[string]*ebpf.Collection
	collectionByPath map[string]*ebpf.Collection
	collstoreMutex   sync.RWMutex
)

func SetCollection(name string, path string, coll *ebpf.Collection) {
	collstoreMutex.Lock()
	defer collstoreMutex.Unlock()
	collectionByName[name] = coll
	collectionByPath[path] = coll
}

func GetCollectionByPath(path string) (*ebpf.Collection, error) {
	collstoreMutex.RLock()
	defer collstoreMutex.RUnlock()
	coll, ok := collectionByPath[path]
	if ok {
		return coll, nil
	}
	return nil, errors.New("collection object not found by path")
}

func GetCollection(name string) (*ebpf.Collection, error) {
	collstoreMutex.RLock()
	defer collstoreMutex.RUnlock()
	coll, ok := collectionByName[name]
	if ok {
		return coll, nil
	}
	return nil, errors.New("collection object not found")
}

func init() {
	collectionByName = make(map[string]*ebpf.Collection)
	collectionByPath = make(map[string]*ebpf.Collection)
}
