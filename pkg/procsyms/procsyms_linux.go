// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package procsyms

import (
	"debug/elf"
	"fmt"
	"sync"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/prometheus/procfs"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
)

// symbolCacheKey is the key for the symbol name cache (Level 2 cache)
type symbolCacheKey struct {
	module string
	offset uint64
}

// procMapCacheSize is the maximum number of PIDs to cache memory maps for
const procMapCacheSize = 1024

// symbolCacheSize is the maximum number of symbol lookups to cache
const symbolCacheSize = 1024

var (
	// symbolCache stores symbol names keyed by module+offset (Level 2 cache)
	symbolCache    *lru.Cache[symbolCacheKey, string]
	setSymbolCache sync.Once

	// procMapCache stores parsed /proc/[pid]/maps entries keyed by PID (Level 1 cache)
	procMapCache    *lru.Cache[int, []*procMapEntry]
	setProcMapCache sync.Once
)

// procMapEntry represents a cached memory region from /proc/[pid]/maps
type procMapEntry struct {
	startAddr uintptr
	endAddr   uintptr
	offset    int64
	pathname  string
}

// initSymbolCache initializes the Level 2 symbol cache (thread-safe, called once)
func initSymbolCache() {
	setSymbolCache.Do(func() {
		c, err := lru.New[symbolCacheKey, string](symbolCacheSize)
		if err != nil {
			logger.GetLogger().Info("failed to initialize symbol cache", logfields.Error, err)
			return
		}
		symbolCache = c
	})
}

// initProcMapCache initializes the Level 1 process map cache (thread-safe, called once)
func initProcMapCache() {
	setProcMapCache.Do(func() {
		c, err := lru.New[int, []*procMapEntry](procMapCacheSize)
		if err != nil {
			logger.GetLogger().Info("failed to initialize proc map cache", logfields.Error, err)
			return
		}
		procMapCache = c
	})
}

// getProcMaps returns the memory maps for a PID, using cache when available
func getProcMaps(pid int) ([]*procMapEntry, error) {
	initProcMapCache()

	// Try cache first
	if procMapCache != nil {
		if maps, ok := procMapCache.Get(pid); ok {
			return maps, nil
		}
	}

	// Cache miss - read from procfs
	p, err := procfs.NewProc(pid)
	if err != nil {
		return nil, fmt.Errorf("can't open /proc/%d", pid)
	}

	rawMaps, err := p.ProcMaps()
	if err != nil {
		return nil, fmt.Errorf("can't get proc/%d/maps", pid)
	}

	if len(rawMaps) == 0 {
		return nil, fmt.Errorf("proc/%d/maps is empty", pid)
	}

	// Convert to our cached format
	maps := make([]*procMapEntry, len(rawMaps))
	for i, m := range rawMaps {
		maps[i] = &procMapEntry{
			startAddr: m.StartAddr,
			endAddr:   m.EndAddr,
			offset:    m.Offset,
			pathname:  m.Pathname,
		}
	}

	// Store in cache
	if procMapCache != nil {
		procMapCache.Add(pid, maps)
	}

	return maps, nil
}

// findMapEntry uses binary search to find the memory map entry containing the given address
func findMapEntry(maps []*procMapEntry, addr uint64) *procMapEntry {
	l, r := 0, len(maps)-1

	for l < r {
		// prevents overflow
		m := l + ((r - l + 1) >> 1)
		if uint64(maps[m].startAddr) < addr {
			l = m
		} else {
			r = m - 1
		}
	}

	return maps[l]
}

// GetFnSymbol returns the FnSym for a given address and PID
func GetFnSymbol(pid int, addr uint64) (*FnSym, error) {
	// Get memory maps (from cache or procfs)
	maps, err := getProcMaps(pid)
	if err != nil {
		return nil, err
	}

	// Find the map entry containing this address
	entry := findMapEntry(maps, addr)

	sym := FnSym{}
	sym.Module = entry.pathname
	sym.Offset = addr - uint64(entry.startAddr) + uint64(entry.offset)

	// Initialize symbol cache if needed
	initSymbolCache()

	// Check symbol cache (Level 2)
	if symbolCache != nil {
		key := symbolCacheKey{
			module: sym.Module,
			offset: sym.Offset,
		}
		if ret, ok := symbolCache.Get(key); ok {
			sym.Name = ret
			return &sym, nil
		}
	}

	// Cache miss - parse ELF to find symbol
	if binary, err := elf.Open(entry.pathname); err == nil {
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

		// Store in symbol cache
		if symbolCache != nil {
			key := symbolCacheKey{
				module: sym.Module,
				offset: sym.Offset,
			}
			symbolCache.Add(key, sym.Name)
		}
	}
	return &sym, nil
}

