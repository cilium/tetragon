// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package policyfilter

import (
	"fmt"
	"os"
	"path"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/option"
	lru "github.com/hashicorp/golang-lru/v2"
)

const (
	CgrpNsMapName      = "tg_cgroup_namespace_map"
	namespaceCacheSize = 1024
)

type NSID struct {
	Namespace string
	Workload  string
	Kind      string
}

// NamespaceMap is a simple wrapper for ebpf.Map so that we can write methods for it
type NamespaceMap struct {
	cgroupIdMap *ebpf.Map
	nsIdMap     *lru.Cache[StateID, NSID]
	nsNameMap   *lru.Cache[NSID, StateID]
	id          StateID
}

// newNamespaceMap returns a new namespace mapping. The namespace map consists of
// two pieces. First a cgroup to ID map. The ID is useful for BPF so we can avoid
// strings in BPF side. Then a stable ID to namespace mapping.
func newNamespaceMap() (*NamespaceMap, error) {
	idCache, err := lru.New[StateID, NSID](namespaceCacheSize)
	if err != nil {
		return nil, fmt.Errorf("create namespace ID cache failed")
	}
	nameCache, err := lru.New[NSID, StateID](namespaceCacheSize)
	if err != nil {
		return nil, fmt.Errorf("create namespace name cache failed")
	}

	objName := config.ExecObj()
	objPath := path.Join(option.Config.HubbleLib, objName)
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, fmt.Errorf("loading spec for %s failed: %w", objPath, err)
	}
	nsMapSpec, ok := spec.Maps[CgrpNsMapName]
	if !ok {
		return nil, fmt.Errorf("%s not found in %s", CgrpNsMapName, objPath)
	}

	ret, err := ebpf.NewMap(nsMapSpec)
	if err != nil {
		return nil, err
	}

	mapDir := bpf.MapPrefixPath()
	pinPath := filepath.Join(mapDir, CgrpNsMapName)
	os.Remove(pinPath)
	os.Mkdir(mapDir, os.ModeDir)
	err = ret.Pin(pinPath)
	if err != nil {
		ret.Close()
		return nil, fmt.Errorf("failed to pin Namespace map in %s: %w", pinPath, err)
	}

	return &NamespaceMap{
		cgroupIdMap: ret,
		nsIdMap:     idCache,
		nsNameMap:   nameCache,
		id:          1,
	}, err
}
