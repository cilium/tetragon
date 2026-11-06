// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux

// Package ldso resolves the shared libraries a dynamically linked ELF binary
// depends on, following the search order of the glibc dynamic loader (see
// ld.so(8)), without executing anything.
//
// Unlike ldd, it works on binaries belonging to a different root filesystem
// (e.g. a container's), as long as lookups are performed through a Root
// confined to it.
package ldso

import (
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"slices"
	"strings"

	telf "github.com/cilium/tetragon/pkg/elf"
)

var (
	// ErrStaticBinary is returned for binaries that are not dynamically linked.
	ErrStaticBinary = errors.New("binary is statically linked")
	// ErrNotNeeded is returned when the binary does not directly depend on
	// the requested library.
	ErrNotNeeded = errors.New("library is not a direct dependency of the binary")
	// ErrMusl is returned by ResolveNeeded when the binary is linked against
	// musl libc. Since musl libc is also the dynamic loader, it can be
	// resolved with ResolveInterpreter.
	ErrMusl = errors.New("binary is linked against musl libc")
	// ErrNotFound is returned when no suitable library can be found.
	ErrNotFound = errors.New("library not found")
)

// maxInterpLen bounds PT_INTERP reads; PATH_MAX is more than enough.
const maxInterpLen = 4096

// ResolveNeeded looks up soname, which must be a direct dependency (DT_NEEDED)
// of binary, and returns its path along with the opened file. The caller must
// close the returned file.
//
// The search order is the one of the glibc dynamic loader:
//  1. DT_RPATH of the binary, if it has no DT_RUNPATH
//  2. DT_RUNPATH of the binary
//  3. /etc/ld.so.cache, unless the binary was linked with -z nodefaultlib
//  4. default library directories, unless the binary was linked with -z nodefaultlib
//
// For directories, the glibc-hwcaps subdirectories supported by the CPU are
// searched first, in priority order. Likewise, cache entries for supported
// glibc-hwcaps subdirectories are preferred over regular ones.
//
// LD_LIBRARY_PATH is not taken into account, as it depends on the environment
// of each process. Candidates not matching the binary's ELF class, data
// encoding and machine are skipped, like the dynamic loader does.
func ResolveNeeded(root Root, binary, soname string) (string, *os.File, error) {
	bf, err := root.Open(binary)
	if err != nil {
		return "", nil, err
	}
	defer bf.Close()

	ef, err := telf.NewSafeELFFile(bf)
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse %q: %w", binary, err)
	}
	defer ef.Close()

	interp, err := interpreter(ef)
	if err != nil {
		return "", nil, fmt.Errorf("failed to read interpreter of %q: %w", binary, err)
	}
	needed, err := ef.DynString(elf.DT_NEEDED)
	if err != nil {
		return "", nil, fmt.Errorf("failed to read dependencies of %q: %w", binary, err)
	}
	if interp == "" && len(needed) == 0 {
		return "", nil, fmt.Errorf("%q: %w", binary, ErrStaticBinary)
	}
	if !slices.Contains(needed, soname) {
		if strings.HasPrefix(path.Base(interp), "ld-musl-") {
			return "", nil, fmt.Errorf("%q: %w", binary, ErrMusl)
		}
		return "", nil, fmt.Errorf("%q does not depend on %q: %w", binary, soname, ErrNotNeeded)
	}

	r := resolver{root: root, binary: binary, ef: ef, hwcaps: hostHwcaps(ef.Machine, ef.Class)}
	if p, f, ok := r.searchDirs(r.runpathDirs, soname); ok {
		return p, f, nil
	}
	if r.noDefaultLib() {
		return "", nil, fmt.Errorf("%q for %q: %w", soname, binary, ErrNotFound)
	}
	if p, f, ok := r.searchCache(soname); ok {
		return p, f, nil
	}
	if p, f, ok := r.searchDirs(func() []string { return defaultDirs(ef) }, soname); ok {
		return p, f, nil
	}
	return "", nil, fmt.Errorf("%q for %q: %w", soname, binary, ErrNotFound)
}

// ResolveInterpreter returns the path of the program interpreter (PT_INTERP)
// of binary, i.e. its dynamic loader, along with the opened file. The caller
// must close the returned file.
//
// This is mostly useful for musl binaries, where libc and the dynamic loader
// are the same object: e.g. on Alpine, the binary depends on
// libc.musl-x86_64.so.1, a symlink to its interpreter /lib/ld-musl-x86_64.so.1.
func ResolveInterpreter(root Root, binary string) (string, *os.File, error) {
	bf, err := root.Open(binary)
	if err != nil {
		return "", nil, err
	}
	defer bf.Close()

	ef, err := telf.NewSafeELFFile(bf)
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse %q: %w", binary, err)
	}
	defer ef.Close()

	interp, err := interpreter(ef)
	if err != nil {
		return "", nil, fmt.Errorf("failed to read interpreter of %q: %w", binary, err)
	}
	if interp == "" {
		return "", nil, fmt.Errorf("%q: %w", binary, ErrStaticBinary)
	}
	if !path.IsAbs(interp) {
		return "", nil, fmt.Errorf("interpreter %q of %q is not an absolute path: %w", interp, binary, ErrNotFound)
	}

	r := resolver{root: root, binary: binary, ef: ef}
	if p, f, ok := r.try(path.Clean(interp)); ok {
		return p, f, nil
	}
	return "", nil, fmt.Errorf("interpreter %q for %q: %w", interp, binary, ErrNotFound)
}

type resolver struct {
	root   Root
	binary string
	ef     *telf.SafeELFFile
	// glibc-hwcaps subdirectories to search, in decreasing priority order
	hwcaps []string
}

func (r *resolver) searchDirs(dirs func() []string, soname string) (string, *os.File, bool) {
	for _, dir := range dirs() {
		for _, sub := range r.hwcaps {
			if p, f, ok := r.try(path.Join(dir, hwcapsDir, sub, soname)); ok {
				return p, f, true
			}
		}
		if p, f, ok := r.try(path.Join(dir, soname)); ok {
			return p, f, true
		}
	}
	return "", nil, false
}

func (r *resolver) searchCache(soname string) (string, *os.File, bool) {
	entries, err := readCache(r.root)
	if err != nil {
		// A missing or broken cache is not fatal: ld.so falls back to the
		// default directories as well.
		return "", nil, false
	}
	// Like ld.so, prefer entries of supported glibc-hwcaps subdirectories,
	// by priority, then regular entries. Entries of unsupported
	// subdirectories are skipped.
	type candidate struct {
		path     string
		priority int
	}
	var candidates []candidate
	for _, e := range entries {
		if e.key != soname || !path.IsAbs(e.value) {
			continue
		}
		priority := len(r.hwcaps)
		if e.hwcaps != "" {
			if priority = slices.Index(r.hwcaps, e.hwcaps); priority < 0 {
				continue
			}
		}
		candidates = append(candidates, candidate{path: e.value, priority: priority})
	}
	slices.SortStableFunc(candidates, func(a, b candidate) int { return a.priority - b.priority })

	for _, c := range candidates {
		if p, f, ok := r.try(c.path); ok {
			return p, f, true
		}
	}
	return "", nil, false
}

// try opens candidate and checks it is a shared object loadable by the binary.
func (r *resolver) try(candidate string) (string, *os.File, bool) {
	f, err := r.root.Open(candidate)
	if err != nil {
		return "", nil, false
	}
	if !compatible(f, r.ef) {
		f.Close()
		return "", nil, false
	}
	return candidate, f, true
}

func compatible(f *os.File, bin *telf.SafeELFFile) bool {
	lib, err := telf.NewSafeELFFile(f)
	if err != nil {
		return false
	}
	defer lib.Close()
	return lib.Type == elf.ET_DYN &&
		lib.Class == bin.Class &&
		lib.Data == bin.Data &&
		lib.Machine == bin.Machine
}

// runpathDirs returns the directories listed in DT_RUNPATH, or in DT_RPATH if
// the former is absent, with dynamic string tokens expanded.
func (r *resolver) runpathDirs() []string {
	entries, err := r.ef.DynString(elf.DT_RUNPATH)
	if err != nil || len(entries) == 0 {
		entries, err = r.ef.DynString(elf.DT_RPATH)
		if err != nil {
			return nil
		}
	}

	var origin string
	if realPath, err := r.root.RealPath(r.binary); err == nil {
		origin = path.Dir(realPath)
	}

	var dirs []string
	for _, entry := range entries {
		for dir := range strings.SplitSeq(entry, ":") {
			for _, d := range expandTokens(dir, origin, r.ef) {
				// Relative entries are relative to the working directory of
				// the process, which we don't know.
				if path.IsAbs(d) {
					dirs = append(dirs, path.Clean(d))
				}
			}
		}
	}
	return dirs
}

func (r *resolver) noDefaultLib() bool {
	flags, err := r.ef.DynValue(elf.DT_FLAGS_1)
	if err != nil {
		return false
	}
	for _, f := range flags {
		if elf.DynFlag1(f)&elf.DF_1_NODEFLIB != 0 {
			return true
		}
	}
	return false
}

// expandTokens expands the dynamic string tokens ld.so supports in
// DT_RUNPATH/DT_RPATH. Since $LIB depends on how glibc was built, it expands
// to all its plausible values. Entries with unknown or unresolvable tokens are
// dropped, as ld.so does.
func expandTokens(dir, origin string, ef *telf.SafeELFFile) []string {
	if !strings.Contains(dir, "$") {
		return []string{dir}
	}

	var lib []string
	if t := multiarchTriplet(ef); t != "" {
		lib = append(lib, "lib/"+t)
	}
	if ef.Class == elf.ELFCLASS64 {
		lib = append(lib, "lib64")
	}
	lib = append(lib, "lib")

	var platform []string
	if p := platformName(ef); p != "" {
		platform = []string{p}
	}
	var originVals []string
	if origin != "" {
		originVals = []string{origin}
	}

	tokens := map[string][]string{
		"ORIGIN":   originVals,
		"LIB":      lib,
		"PLATFORM": platform,
	}

	res := []string{""}
	for len(dir) > 0 {
		i := strings.IndexByte(dir, '$')
		if i < 0 {
			res = appendAll(res, dir)
			break
		}
		res = appendAll(res, dir[:i])
		dir = dir[i+1:]

		var name string
		if strings.HasPrefix(dir, "{") {
			end := strings.IndexByte(dir, '}')
			if end < 0 {
				return nil
			}
			name, dir = dir[1:end], dir[end+1:]
		} else {
			end := strings.IndexFunc(dir, func(c rune) bool {
				return (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_'
			})
			if end < 0 {
				end = len(dir)
			}
			name, dir = dir[:end], dir[end:]
		}

		vals := tokens[name]
		if len(vals) == 0 {
			return nil
		}
		var next []string
		for _, prefix := range res {
			for _, v := range vals {
				next = append(next, prefix+v)
			}
		}
		res = next
	}
	return res
}

func appendAll(prefixes []string, s string) []string {
	for i := range prefixes {
		prefixes[i] += s
	}
	return prefixes
}

// defaultDirs returns the directories searched last by ld.so. Since the exact
// list depends on how glibc was built (e.g. Debian uses multiarch directories,
// Fedora uses lib64), we include all the common layouts: incompatible
// libraries are discarded anyway.
func defaultDirs(ef *telf.SafeELFFile) []string {
	var dirs []string
	if t := multiarchTriplet(ef); t != "" {
		dirs = append(dirs, "/lib/"+t, "/usr/lib/"+t)
	}
	if ef.Class == elf.ELFCLASS64 {
		dirs = append(dirs, "/lib64", "/usr/lib64")
	}
	return append(dirs, "/lib", "/usr/lib")
}

func multiarchTriplet(ef *telf.SafeELFFile) string {
	switch {
	case ef.Machine == elf.EM_X86_64 && ef.Class == elf.ELFCLASS64:
		return "x86_64-linux-gnu"
	case ef.Machine == elf.EM_X86_64 && ef.Class == elf.ELFCLASS32:
		return "x86_64-linux-gnux32"
	case ef.Machine == elf.EM_386:
		return "i386-linux-gnu"
	case ef.Machine == elf.EM_AARCH64:
		return "aarch64-linux-gnu"
	case ef.Machine == elf.EM_ARM:
		return "arm-linux-gnueabihf"
	}
	return ""
}

// platformName returns the value of AT_PLATFORM for the binary's machine.
func platformName(ef *telf.SafeELFFile) string {
	switch {
	case ef.Machine == elf.EM_X86_64 && ef.Class == elf.ELFCLASS64:
		return "x86_64"
	case ef.Machine == elf.EM_AARCH64:
		return "aarch64"
	}
	return ""
}

// interpreter returns the PT_INTERP of the binary, or "" if it has none.
func interpreter(ef *telf.SafeELFFile) (string, error) {
	for _, p := range ef.Progs {
		if p.Type != elf.PT_INTERP {
			continue
		}
		if p.Filesz > maxInterpLen {
			return "", fmt.Errorf("PT_INTERP too long: %d bytes", p.Filesz)
		}
		data, err := io.ReadAll(p.Open())
		if err != nil {
			return "", err
		}
		return strings.TrimRight(string(data), "\x00"), nil
	}
	return "", nil
}
