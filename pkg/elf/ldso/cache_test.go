// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux

package ldso

import (
	"bytes"
	"encoding/binary"
	"os"
	"os/exec"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

// buildCache serializes entries in the ld.so.cache new format.
func buildCache(entries []cacheEntry) []byte {
	order := binary.NativeEndian
	var buf bytes.Buffer

	var strs bytes.Buffer
	strBase := newCacheHeaderSize + len(entries)*newCacheEntrySize
	addStr := func(s string) uint32 {
		off := uint32(strBase + strs.Len())
		strs.WriteString(s)
		strs.WriteByte(0)
		return off
	}

	var hdr [newCacheHeaderSize]byte
	copy(hdr[:], newCacheMagic)
	order.PutUint32(hdr[newCacheNlibsOffset:], uint32(len(entries)))
	var ents bytes.Buffer
	for _, e := range entries {
		var ent [newCacheEntrySize]byte
		order.PutUint32(ent[0:], 0x0303) // FLAG_ELF_LIBC6 | FLAG_X8664_LIB64
		order.PutUint32(ent[4:], addStr(e.key))
		order.PutUint32(ent[8:], addStr(e.value))
		ents.Write(ent[:])
	}
	order.PutUint32(hdr[24:], uint32(strs.Len()))

	buf.Write(hdr[:])
	buf.Write(ents.Bytes())
	buf.Write(strs.Bytes())
	return buf.Bytes()
}

func TestParseCache(t *testing.T) {
	entries := []cacheEntry{
		{key: "libfoo.so.1", value: "/usr/lib/libfoo.so.1"},
		{key: "libc.so.6", value: "/lib/x86_64-linux-gnu/libc.so.6"},
		{key: "libc.so.6", value: "/lib32/libc.so.6"},
	}

	data := buildCache(entries)
	got, err := parseCache(data)
	require.NoError(t, err)
	require.Equal(t, entries, got)

	// Every truncation must be reported as an error, never panic.
	for i := range data {
		_, err := parseCache(data[:i])
		require.Error(t, err, "truncated at %d", i)
	}

	empty, err := parseCache(buildCache(nil))
	require.NoError(t, err)
	require.Empty(t, empty)
}

func TestParseCacheMalformed(t *testing.T) {
	order := binary.NativeEndian
	valid := buildCache([]cacheEntry{{key: "liba.so", value: "/lib/liba.so"}})

	tests := map[string]func([]byte){
		"bad magic":         func(d []byte) { d[0] = 'X' },
		"huge nlibs":        func(d []byte) { order.PutUint32(d[newCacheNlibsOffset:], 0xffffffff) },
		"key out of bounds": func(d []byte) { order.PutUint32(d[newCacheHeaderSize+4:], 0xffffffff) },
		"unterminated":      func(d []byte) { d[len(d)-1] = 'x' },
	}
	for name, corrupt := range tests {
		t.Run(name, func(t *testing.T) {
			d := bytes.Clone(valid)
			corrupt(d)
			_, err := parseCache(d)
			require.ErrorIs(t, err, errBadCache)
		})
	}

	t.Run("compat format is not supported", func(t *testing.T) {
		_, err := parseCache(compatCache(valid))
		require.ErrorIs(t, err, errBadCache)
	})
}

// TestParseHostCache checks the parser against ldconfig's view of the host
// cache.
func TestParseHostCache(t *testing.T) {
	if _, err := os.Stat(cachePath); err != nil {
		t.Skipf("no host cache: %v", err)
	}
	ldconfig, err := exec.LookPath("ldconfig")
	if err != nil {
		t.Skip("ldconfig not available")
	}
	out, err := exec.Command(ldconfig, "-p").Output()
	if err != nil {
		t.Skipf("ldconfig -p failed: %v", err)
	}

	// e.g. "\tlibc.so.6 (libc6,x86-64) => /lib/x86_64-linux-gnu/libc.so.6"
	re := regexp.MustCompile(`(?m)^\s+(\S+) \(.*\) => (\S+)$`)
	var want []cacheEntry
	for _, m := range re.FindAllStringSubmatch(string(out), -1) {
		want = append(want, cacheEntry{key: m[1], value: m[2]})
	}
	require.NotEmpty(t, want)

	got, err := readCache(HostRoot())
	require.NoError(t, err)
	require.ElementsMatch(t, want, got)
}

// compatCache prepends an empty old format header to a new format cache, as
// ldconfig < 2.32 does by default.
func compatCache(cache []byte) []byte {
	return append([]byte("ld.so-1.7.0\x00\x00\x00\x00\x00"), cache...)
}
