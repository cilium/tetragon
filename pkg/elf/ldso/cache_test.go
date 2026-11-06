// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux

package ldso

import (
	"bytes"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// buildCache serializes entries in the ld.so.cache new format. Entries with
// hwcaps set are flagged as glibc-hwcaps ones, with the subdirectory names
// stored in a cache extension, as ldconfig >= 2.33 does.
func buildCache(entries []cacheEntry) []byte {
	order := binary.NativeEndian

	var strs bytes.Buffer
	strBase := newCacheHeaderSize + len(entries)*newCacheEntrySize
	addStr := func(s string) uint32 {
		off := uint32(strBase + strs.Len())
		strs.WriteString(s)
		strs.WriteByte(0)
		return off
	}

	var hwcaps []string
	var ents bytes.Buffer
	for _, e := range entries {
		var ent [newCacheEntrySize]byte
		order.PutUint32(ent[0:], 0x0303) // FLAG_ELF_LIBC6 | FLAG_X8664_LIB64
		order.PutUint32(ent[4:], addStr(e.key))
		order.PutUint32(ent[8:], addStr(e.value))
		if e.hwcaps != "" {
			idx := slices.Index(hwcaps, e.hwcaps)
			if idx < 0 {
				idx = len(hwcaps)
				hwcaps = append(hwcaps, e.hwcaps)
			}
			order.PutUint64(ent[newCacheEntryHwcapOffset:], hwcapExtension|uint64(idx))
		}
		ents.Write(ent[:])
	}
	var hwcapsOffs []uint32
	for _, h := range hwcaps {
		hwcapsOffs = append(hwcapsOffs, addStr(h))
	}

	var hdr [newCacheHeaderSize]byte
	copy(hdr[:], newCacheMagic)
	order.PutUint32(hdr[newCacheNlibsOffset:], uint32(len(entries)))
	order.PutUint32(hdr[24:], uint32(strs.Len()))

	var buf bytes.Buffer
	buf.Write(hdr[:])
	buf.Write(ents.Bytes())
	buf.Write(strs.Bytes())

	if len(hwcaps) > 0 {
		for buf.Len()%4 != 0 {
			buf.WriteByte(0)
		}
		ext := buf.Len()
		data := buf.Bytes()
		order.PutUint32(data[newCacheExtensionOffset:], uint32(ext))

		arrayOff := ext + cacheExtensionHeaderSize + cacheExtensionSectionSize
		for _, v := range []uint32{
			cacheExtensionMagic, 1, // header: magic, count
			cacheExtensionTagGlibcHwcaps, 0, uint32(arrayOff), uint32(4 * len(hwcaps)), // section
		} {
			buf.Write(order.AppendUint32(nil, v))
		}
		for _, off := range hwcapsOffs {
			buf.Write(order.AppendUint32(nil, off))
		}
	}
	return buf.Bytes()
}

// cacheEntryHwcap returns the hwcap field of the i-th entry of cache.
func cacheEntryHwcap(cache []byte, i int) []byte {
	off := newCacheHeaderSize + i*newCacheEntrySize + newCacheEntryHwcapOffset
	return cache[off : off+8]
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

func TestParseCacheHwcaps(t *testing.T) {
	order := binary.NativeEndian
	entries := []cacheEntry{
		{key: "libc.so.6", value: "/usr/lib64/glibc-hwcaps/x86-64-v3/libc.so.6", hwcaps: "x86-64-v3"},
		{key: "libc.so.6", value: "/usr/lib64/glibc-hwcaps/x86-64-v2/libc.so.6", hwcaps: "x86-64-v2"},
		{key: "libc.so.6", value: "/usr/lib64/libc.so.6"},
		{key: "libm.so.6", value: "/usr/lib64/glibc-hwcaps/x86-64-v3/libm.so.6", hwcaps: "x86-64-v3"},
	}
	valid := buildCache(entries)

	got, err := parseCache(valid)
	require.NoError(t, err)
	require.Equal(t, entries, got)

	// Every truncation must be reported as an error, or at worst drop
	// glibc-hwcaps entries, never panic.
	for i := range valid {
		got, err := parseCache(valid[:i])
		if err == nil {
			require.Subset(t, entries, got, "truncated at %d", i)
		}
	}

	regular := []cacheEntry{entries[2]}
	tests := map[string]func([]byte){
		"no extension": func(d []byte) { order.PutUint32(d[newCacheExtensionOffset:], 0) },
		"extension out of bounds": func(d []byte) {
			order.PutUint32(d[newCacheExtensionOffset:], uint32(len(d)))
		},
		"bad extension magic": func(d []byte) {
			d[order.Uint32(d[newCacheExtensionOffset:])] ^= 0xff
		},
		"huge section count": func(d []byte) {
			order.PutUint32(d[order.Uint32(d[newCacheExtensionOffset:])+4:], 0xffffffff)
		},
	}
	for name, corrupt := range tests {
		t.Run(name, func(t *testing.T) {
			d := bytes.Clone(valid)
			corrupt(d)
			got, err := parseCache(d)
			require.NoError(t, err)
			require.Equal(t, regular, got)
		})
	}

	t.Run("index out of bounds", func(t *testing.T) {
		d := bytes.Clone(valid)
		order.PutUint64(cacheEntryHwcap(d, 0), hwcapExtension|42)
		got, err := parseCache(d)
		require.NoError(t, err)
		require.Equal(t, entries[1:], got)
	})

	t.Run("ISA level bits are ignored", func(t *testing.T) {
		d := bytes.Clone(valid)
		order.PutUint64(cacheEntryHwcap(d, 0), hwcapExtension|uint64(3)<<32)
		got, err := parseCache(d)
		require.NoError(t, err)
		require.Equal(t, entries, got)
	})

	t.Run("legacy hwcaps entries are dropped", func(t *testing.T) {
		d := bytes.Clone(valid)
		order.PutUint64(cacheEntryHwcap(d, 2), 1<<3)
		got, err := parseCache(d)
		require.NoError(t, err)
		require.Equal(t, []cacheEntry{entries[0], entries[1], entries[3]}, got)
	})
}

// ldconfigEntries returns the entries of the given cache, as listed by
// `ldconfig -p`.
func ldconfigEntries(t *testing.T, ldconfig, cache string) []cacheEntry {
	t.Helper()
	out, err := exec.Command(ldconfig, "-p", "-C", cache).Output()
	if err != nil {
		t.Skipf("ldconfig -p failed: %v", err)
	}

	// e.g. "\tlibc.so.6 (libc6,x86-64) => /lib/x86_64-linux-gnu/libc.so.6"
	// or "\tlibc.so.6 (libc6,x86-64, hwcap: "x86-64-v3") => /usr/lib64/glibc-hwcaps/x86-64-v3/libc.so.6"
	re := regexp.MustCompile(`(?m)^\s+(\S+) \((.*)\) => (\S+)$`)
	hwcapRe := regexp.MustCompile(`hwcap: (\S+)`)
	var entries []cacheEntry
	for _, m := range re.FindAllStringSubmatch(string(out), -1) {
		e := cacheEntry{key: m[1], value: m[3]}
		if h := hwcapRe.FindStringSubmatch(m[2]); h != nil {
			name, err := strconv.Unquote(h[1])
			if err != nil {
				// legacy hwcaps entries (e.g. "hwcap: 0x..."), dropped by
				// the parser
				continue
			}
			e.hwcaps = name
		}
		entries = append(entries, e)
	}
	return entries
}

func lookupLdconfig(t *testing.T) string {
	t.Helper()
	ldconfig, err := exec.LookPath("ldconfig")
	if err != nil {
		t.Skip("ldconfig not available")
	}
	return ldconfig
}

// TestParseHostCache checks the parser against ldconfig's view of the host
// cache.
func TestParseHostCache(t *testing.T) {
	if _, err := os.Stat(cachePath); err != nil {
		t.Skipf("no host cache: %v", err)
	}
	want := ldconfigEntries(t, lookupLdconfig(t), cachePath)
	require.NotEmpty(t, want)

	got, err := readCache(HostRoot())
	require.NoError(t, err)
	require.ElementsMatch(t, want, got)
}

// TestParseLdconfigHwcapsCache checks the parser against ldconfig's view of a
// cache generated by ldconfig itself, with glibc-hwcaps entries.
func TestParseLdconfigHwcapsCache(t *testing.T) {
	ldconfig := lookupLdconfig(t)
	if _, err := os.Stat(cachePath); err != nil {
		t.Skipf("no host cache: %v", err)
	}
	// Any shared library will do: take one from the host cache.
	var src string
	for _, e := range ldconfigEntries(t, ldconfig, cachePath) {
		if e.hwcaps == "" && strings.HasPrefix(e.key, "libz.so") {
			src = e.value
			break
		}
	}
	if src == "" {
		t.Skip("no libz in the host cache")
	}
	lib, err := os.ReadFile(src)
	require.NoError(t, err)

	dir := t.TempDir()
	libdir := filepath.Join(dir, "lib")
	name := filepath.Base(src)
	for _, sub := range []string{"", "glibc-hwcaps/x86-64-v3", "glibc-hwcaps/x86-64-v2"} {
		d := filepath.Join(libdir, sub)
		require.NoError(t, os.MkdirAll(d, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(d, name), lib, 0o644))
	}
	conf := filepath.Join(dir, "ld.so.conf")
	require.NoError(t, os.WriteFile(conf, []byte(libdir+"\n"), 0o644))
	cache := filepath.Join(dir, "ld.so.cache")
	if out, err := exec.Command(ldconfig, "-X", "-C", cache, "-f", conf).CombinedOutput(); err != nil {
		t.Skipf("ldconfig failed: %v: %s", err, out)
	}

	want := ldconfigEntries(t, ldconfig, cache)
	var hwcaps []string
	for _, e := range want {
		if strings.HasPrefix(e.value, libdir) && e.hwcaps != "" {
			hwcaps = append(hwcaps, e.hwcaps)
		}
	}
	if len(hwcaps) == 0 {
		t.Skip("ldconfig does not support glibc-hwcaps")
	}
	require.ElementsMatch(t, []string{"x86-64-v3", "x86-64-v2"}, hwcaps)

	data, err := os.ReadFile(cache)
	require.NoError(t, err)
	got, err := parseCache(data)
	require.NoError(t, err)
	require.ElementsMatch(t, want, got)
}

// compatCache prepends an empty old format header to a new format cache, as
// ldconfig < 2.32 does by default.
func compatCache(cache []byte) []byte {
	return append([]byte("ld.so-1.7.0\x00\x00\x00\x00\x00"), cache...)
}
