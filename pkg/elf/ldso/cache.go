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
// where string offsets are relative to the start of the header.
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
	newCacheHeaderSize  = 48
	newCacheNlibsOffset = 20
	// struct file_entry_new: int32_t flags; uint32_t key, value;
	// uint32_t osversion; uint64_t hwcap;
	newCacheEntrySize = 24
)

var errBadCache = errors.New("malformed ld.so.cache")

// cacheEntry maps a soname (key) to the path of a library providing it
// (value). Entries for other architectures may be present: callers are
// expected to validate the library itself.
type cacheEntry struct {
	key   string
	value string
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
		entries = append(entries, cacheEntry{key: key, value: value})
	}
	return entries, nil
}
