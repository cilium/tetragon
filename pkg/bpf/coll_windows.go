//go:build windows

package bpf

import (
	"errors"

	"github.com/cilium/ebpf"
)

type CollectionStore struct {
	collMap map[string]*ebpf.Collection
}

var (
	store CollectionStore
)

func SetCollection(name string, coll *ebpf.Collection) {
	store.collMap[name] = coll
}

func GetCollection(name string) (*ebpf.Collection, error) {
	coll, ok := store.collMap[name]
	if ok {
		return coll, nil
	}
	return nil, errors.New("Collection object not found")
}

func init() {
	store.collMap = make(map[string]*ebpf.Collection)
}
