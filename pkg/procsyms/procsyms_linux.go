// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package procsyms

import (
	"debug/elf"
	"fmt"
	"sync"

	"github.com/cilium/tetragon/pkg/logger"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/prometheus/procfs"
)

var (
	cache *lru.Cache[struct {
		module string
		offset uint64
	}, string]
	setCache sync.Once
)

// GetFnSymbol -- returns the FnSym for a given address and PID
func GetFnSymbol(pid int, addr uint64) (*FnSym, error) {
	// TODO: Think about cache [pid+addr] -> [module+offset]
	p, err := procfs.NewProc(pid)
	if err != nil {
		return nil, fmt.Errorf("Can't open /proc/%d", pid)
	}
	maps, err := p.ProcMaps()
	if err != nil {
		return nil, fmt.Errorf("Can't get proc/%d/maps", pid)
	}

	if len(maps) == 0 {
		return nil, fmt.Errorf("proc/%d/maps is empty", pid)
	}

	// binary search
	l, r := 0, len(maps)-1

	for l < r {
		// prevents overflow
		m := l + ((r - l + 1) >> 1)
		if uint64(maps[m].StartAddr) < addr {
			l = m
		} else {
			r = m - 1
		}
	}

	entry := maps[l]
	sym := FnSym{}
	sym.Module = entry.Pathname
	sym.Offset = addr - uint64(entry.StartAddr) + uint64(entry.Offset)

	// Initialize symbol cache
	setCache.Do(func() {
		c, err := lru.New[struct {
			module string
			offset uint64
		}, string](1024)
		if err == nil {
			cache = c
		} else {
			logger.GetLogger().Infof("failed to initialize cache: %s", err)
		}

	})

	if cache != nil {
		// cache hit
		key := struct {
			module string
			offset uint64
		}{
			module: sym.Module,
			offset: sym.Offset,
		}
		if ret, ok := cache.Get(key); ok {
			sym.Name = ret
			return &sym, nil
		}
	}

	if binary, err := elf.Open(entry.Pathname); err == nil {
		defer binary.Close()
		syms, _ := binary.Symbols()
		if dsyms, err := binary.DynamicSymbols(); err == nil {
			syms = append(syms, dsyms...)
		}
		for _, s := range syms {
			if (s.Info & byte(elf.STT_FUNC)) == 0 {
				continue
			}
			// Check special section indices
			if int(s.Section) < 0 || int(s.Section) >= len(binary.Sections) {
				continue
			}
			// Calculate symbol offset
			section := binary.Sections[s.Section]
			symOffset := s.Value - section.Addr + section.Offset
			// Symbols are unordered by Value, so using linear scan
			if symOffset <= sym.Offset && sym.Offset < (symOffset+s.Size) {
				sym.Name = s.Name
				break
			}
		}

		// Store sym in cache, no matter was it found or not.
		key := struct {
			module string
			offset uint64
		}{
			module: sym.Module,
			offset: sym.Offset,
		}
		cache.Add(key, sym.Name)
	}
	return &sym, nil
}
