// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package sensors

import (
	"fmt"
	"path/filepath"

	"github.com/cilium/ebpf"
)

type Selector struct {
	MapName   string
	Selectors [128]byte
}

func SetFilter(mapDir string, mapName string, selectors [128]byte) error {
	selectorMap, err := ebpf.LoadPinnedMap(filepath.Join(mapDir, mapName), nil)
	if err != nil {
		return fmt.Errorf("failed to open selector map '%s': %w", mapName, err)
	}
	defer selectorMap.Close()

	return selectorMap.Update(uint32(0), selectors, ebpf.UpdateAny)
}
