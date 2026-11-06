// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux

package ldso

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Parser for glibc's /etc/ld.so.cache, see glibc's sysdeps/generic/dl-cache.h.
//
// Only the new format, written by default by ldconfig since glibc 2.32, is
// supported:
//
//	[cache_file_new header][file_entry_new...][strings]
//
// where string offsets are relative to the start of the header. Entries
// for glibc-hwcaps subdirectories (glibc >= 2.33) are flagged in their hwcap
// field, which then holds an index in the list of subdirectory names found in
// the cache extension section pointed to by the header.
//
// The old and compat formats (old format followed by the new one), written
// by default by older glibc versions, are intentionally not supported: our
// only user, the uprobe `sopath` override, requires glibc >= 2.34 anyway.
// Such caches are reported as malformed, and the resolver falls back to the
// default library directories, as ld.so does.

const (
	cachePath = "/etc/ld.so.cache"
	// Upper bound on the cache size we are willing to read: the file may come
	// from an untrusted root. Real caches are in the 10KiB-1MiB range.
	cacheMaxSize = 16 << 20

	newCacheMagic = "glibc-ld.so.cache1.1"
	// struct cache_file_new: char magic[17]; char version[3]; uint32_t nlibs;
	// uint32_t len_strings; uint8_t flags; uint8_t padding[3];
	// uint32_t extension_offset; uint32_t unused[3];
	newCacheHeaderSize      = 48
	newCacheNlibsOffset     = 20
	newCacheExtensionOffset = 32
	// struct file_entry_new: int32_t flags; uint32_t key, value;
	// uint32_t osversion; uint64_t hwcap;
	newCacheEntrySize        = 24
	newCacheEntryHwcapOffset = 16

	// struct cache_extension: uint32_t magic; uint32_t count;
	// struct cache_extension_section sections[];
	cacheExtensionMagic      = 0xeaa42174
	cacheExtensionHeaderSize = 8
	// struct cache_extension_section: uint32_t tag; uint32_t flags;
	// uint32_t offset; uint32_t size;
	cacheExtensionSectionSize = 16
	// The section holds an array of uint32_t string offsets, naming the
	// glibc-hwcaps subdirectories.
	cacheExtensionTagGlibcHwcaps = 1

	// DL_CACHE_HWCAP_EXTENSION: if set (and no other bit in the upper 32 bits
	// but the ISA level ones), the lower 32 bits of hwcap are an index in the
	// glibc-hwcaps subdirectories.
	hwcapExtension     = uint64(1) << 62
	hwcapISALevelMask  = uint64(1)<<10 - 1
	hwcapExtensionMask = 0xffffffff
)

var errBadCache = errors.New("malformed ld.so.cache")

// cacheEntry maps a soname (key) to the path of a library providing it
// (value). Entries for other architectures may be present: callers are
// expected to validate the library itself.
type cacheEntry struct {
	key   string
	value string
	// hwcaps is the glibc-hwcaps subdirectory the entry belongs to (e.g.
	// "x86-64-v3"), or "" for regular entries.
	hwcaps string
}

// readCache reads and parses the ld.so.cache found in root.
func readCache(root Root) ([]cacheEntry, error) {
	f, err := root.Open(cachePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, cacheMaxSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > cacheMaxSize {
		return nil, fmt.Errorf("%w: larger than %d bytes", errBadCache, cacheMaxSize)
	}
	return parseCache(data)
}

func parseCache(data []byte) ([]cacheEntry, error) {
	// The cache is written by ldconfig in the native byte order.
	order := binary.NativeEndian

	cache := data
	if !bytes.HasPrefix(cache, []byte(newCacheMagic)) {
		return nil, fmt.Errorf("%w: unsupported format", errBadCache)
	}
	if len(cache) < newCacheHeaderSize {
		return nil, fmt.Errorf("%w: truncated header", errBadCache)
	}
	nlibs := uint64(order.Uint32(cache[newCacheNlibsOffset:]))
	if newCacheHeaderSize+nlibs*newCacheEntrySize > uint64(len(cache)) {
		return nil, fmt.Errorf("%w: entries exceed file size", errBadCache)
	}

	str := func(off uint32) (string, error) {
		if uint64(off) >= uint64(len(cache)) {
			return "", fmt.Errorf("%w: string offset %d out of bounds", errBadCache, off)
		}
		s, _, ok := bytes.Cut(cache[off:], []byte{0})
		if !ok {
			return "", fmt.Errorf("%w: unterminated string at offset %d", errBadCache, off)
		}
		return string(s), nil
	}

	hwcaps := parseCacheHwcaps(cache, str)

	entries := make([]cacheEntry, 0, nlibs)
	for i := range nlibs {
		e := cache[newCacheHeaderSize+i*newCacheEntrySize:]
		key, err := str(order.Uint32(e[4:]))
		if err != nil {
			return nil, err
		}
		value, err := str(order.Uint32(e[8:]))
		if err != nil {
			return nil, err
		}

		entry := cacheEntry{key: key, value: value}
		hwcap := order.Uint64(e[newCacheEntryHwcapOffset:])
		switch {
		case (hwcap>>32)&^hwcapISALevelMask == hwcapExtension>>32:
			idx := hwcap & hwcapExtensionMask
			if idx >= uint64(len(hwcaps)) {
				// Missing or broken extension: ld.so ignores the entry.
				continue
			}
			entry.hwcaps = hwcaps[idx]
		case hwcap != 0:
			// Legacy hwcaps (e.g. "haswell" or "tls" subdirectories),
			// removed in glibc 2.37: ignore the entry, distros don't ship
			// libc there.
			continue
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// parseCacheHwcaps returns the glibc-hwcaps subdirectory names stored in the
// cache extension, if any. Like ld.so, a missing or malformed extension is not
// an error: entries referring to it are just ignored.
func parseCacheHwcaps(cache []byte, str func(uint32) (string, error)) []string {
	order := binary.NativeEndian
	u32 := func(off uint64) (uint32, bool) {
		if off+4 > uint64(len(cache)) {
			return 0, false
		}
		return order.Uint32(cache[off:]), true
	}

	ext := uint64(order.Uint32(cache[newCacheExtensionOffset:]))
	if ext == 0 {
		return nil
	}
	if magic, ok := u32(ext); !ok || magic != cacheExtensionMagic {
		return nil
	}
	count, ok := u32(ext + 4)
	if !ok || ext+cacheExtensionHeaderSize+uint64(count)*cacheExtensionSectionSize > uint64(len(cache)) {
		return nil
	}
	for i := range uint64(count) {
		sec := ext + cacheExtensionHeaderSize + i*cacheExtensionSectionSize
		tag, ok1 := u32(sec)
		off, ok2 := u32(sec + 8)
		size, ok3 := u32(sec + 12)
		if !ok1 || !ok2 || !ok3 {
			return nil
		}
		if tag != cacheExtensionTagGlibcHwcaps {
			continue
		}
		if size%4 != 0 || uint64(off)+uint64(size) > uint64(len(cache)) {
			return nil
		}
		names := make([]string, 0, size/4)
		for j := uint64(0); j < uint64(size); j += 4 {
			name, err := str(order.Uint32(cache[uint64(off)+j:]))
			if err != nil {
				return nil
			}
			names = append(names, name)
		}
		return names
	}
	return nil
}
