// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux

package ldso

import (
	"bufio"
	"bytes"
	"debug/elf"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	telf "github.com/cilium/tetragon/pkg/elf"
	"github.com/cilium/tetragon/pkg/testutils"
)

func TestResolveNeeded(t *testing.T) {
	const libc = "libc.so.6"
	lib32 := elfSpec{class: elf.ELFCLASS32, machine: elf.EM_386}
	libArm := elfSpec{machine: elf.EM_AARCH64}
	cache := func(entries ...cacheEntry) []byte { return buildCache(entries) }

	tests := []struct {
		name    string
		files   map[string]any
		binary  string
		soname  string
		want    string
		wantErr error
	}{
		{
			name: "debian multiarch default dir",
			files: map[string]any{
				"/usr/bin/app":                        exe(libc),
				"/usr/lib/x86_64-linux-gnu/libc.so.6": lib64,
				"/lib":                                "usr/lib",
			},
			want: "/lib/x86_64-linux-gnu/libc.so.6",
		},
		{
			name: "fedora lib64 default dir",
			files: map[string]any{
				"/usr/bin/app":         exe(libc),
				"/usr/lib64/libc.so.6": lib64,
				"/lib64":               "usr/lib64",
			},
			want: "/lib64/libc.so.6",
		},
		{
			name: "incompatible libraries are skipped",
			files: map[string]any{
				"/usr/bin/app":       exe(libc),
				"/lib64/libc.so.6":   lib32,
				"/lib/libc.so.6":     libArm,
				"/usr/lib/libc.so.6": lib64,
			},
			want: "/usr/lib/libc.so.6",
		},
		{
			name: "executables are not libraries",
			files: map[string]any{
				"/usr/bin/app":       exe(libc),
				"/lib64/libc.so.6":   elfSpec{typ: elf.ET_EXEC},
				"/usr/lib/libc.so.6": lib64,
			},
			want: "/usr/lib/libc.so.6",
		},
		{
			name: "non-ELF candidates are skipped",
			files: map[string]any{
				"/usr/bin/app":       exe(libc),
				"/lib64/libc.so.6":   []byte("GROUP ( /lib64/libc.so.6.real )"),
				"/usr/lib/libc.so.6": lib64,
			},
			want: "/usr/lib/libc.so.6",
		},
		{
			name: "symlinked library keeps the soname path",
			files: map[string]any{
				"/usr/bin/app":        exe(libc),
				"/lib64/libc.so.6":    "libc-2.31.so",
				"/lib64/libc-2.31.so": lib64,
			},
			want: "/lib64/libc.so.6",
		},
		{
			name: "cache wins over default dirs",
			files: map[string]any{
				"/usr/bin/app":         exe(libc),
				"/opt/glibc/libc.so.6": lib64,
				"/lib64/libc.so.6":     lib64,
				"/etc/ld.so.cache":     cache(cacheEntry{key: libc, value: "/opt/glibc/libc.so.6"}),
			},
			want: "/opt/glibc/libc.so.6",
		},
		{
			name: "cache entries for other arches are skipped",
			files: map[string]any{
				"/usr/bin/app":         exe(libc),
				"/lib32/libc.so.6":     lib32,
				"/opt/glibc/libc.so.6": lib64,
				"/lib64/libc.so.6":     lib64,
				"/etc/ld.so.cache": cache(
					cacheEntry{key: "libother.so", value: "/opt/glibc/libc.so.6"},
					cacheEntry{key: libc, value: "/lib32/libc.so.6"},
					cacheEntry{key: libc, value: "relative/libc.so.6"},
					cacheEntry{key: libc, value: "/missing/libc.so.6"},
					cacheEntry{key: libc, value: "/opt/glibc/libc.so.6"},
				),
			},
			want: "/opt/glibc/libc.so.6",
		},
		{
			name: "compat cache falls back to default dirs",
			files: map[string]any{
				"/usr/bin/app":         exe(libc),
				"/opt/glibc/libc.so.6": lib64,
				"/lib64/libc.so.6":     lib64,
				"/etc/ld.so.cache":     compatCache(cache(cacheEntry{key: libc, value: "/opt/glibc/libc.so.6"})),
			},
			want: "/lib64/libc.so.6",
		},
		{
			name: "broken cache falls back to default dirs",
			files: map[string]any{
				"/usr/bin/app":     exe(libc),
				"/lib64/libc.so.6": lib64,
				"/etc/ld.so.cache": []byte("garbage"),
			},
			want: "/lib64/libc.so.6",
		},
		{
			name: "runpath wins over cache",
			files: map[string]any{
				"/usr/bin/app":           func() elfSpec { s := exe(libc); s.runpath = "/nope:/opt/app/lib"; return s }(),
				"/opt/app/lib/libc.so.6": lib64,
				"/opt/glibc/libc.so.6":   lib64,
				"/etc/ld.so.cache":       cache(cacheEntry{key: libc, value: "/opt/glibc/libc.so.6"}),
			},
			want: "/opt/app/lib/libc.so.6",
		},
		{
			name: "runpath with $ORIGIN of symlinked binary",
			files: map[string]any{
				"/usr/bin/app":           "../../opt/app/bin/app",
				"/opt/app/bin/app":       func() elfSpec { s := exe(libc); s.runpath = "$ORIGIN/../lib"; return s }(),
				"/opt/app/lib/libc.so.6": lib64,
				"/lib64/libc.so.6":       lib64,
			},
			want: "/opt/app/lib/libc.so.6",
		},
		{
			name: "rpath used without runpath",
			files: map[string]any{
				"/usr/bin/app":         func() elfSpec { s := exe(libc); s.rpath = "/opt/rpath"; return s }(),
				"/opt/rpath/libc.so.6": lib64,
				"/lib64/libc.so.6":     lib64,
			},
			want: "/opt/rpath/libc.so.6",
		},
		{
			name: "rpath ignored with runpath",
			files: map[string]any{
				"/usr/bin/app": func() elfSpec {
					s := exe(libc)
					s.rpath = "/opt/rpath"
					s.runpath = "/opt/runpath"
					return s
				}(),
				"/opt/rpath/libc.so.6": lib64,
				"/lib64/libc.so.6":     lib64,
			},
			want: "/lib64/libc.so.6",
		},
		{
			name: "relative runpath entries are ignored",
			files: map[string]any{
				"/usr/bin/app":     func() elfSpec { s := exe(libc); s.runpath = "lib"; return s }(),
				"/lib/libc.so.6":   lib64,
				"/lib64/libc.so.6": lib64,
			},
			want: "/lib64/libc.so.6",
		},
		{
			name: "nodefaultlib",
			files: map[string]any{
				"/usr/bin/app":     func() elfSpec { s := exe(libc); s.flags1 = elf.DF_1_NODEFLIB; return s }(),
				"/lib64/libc.so.6": lib64,
			},
			wantErr: ErrNotFound,
		},
		{
			name: "not found",
			files: map[string]any{
				"/usr/bin/app":     exe(libc),
				"/lib64/libc.so.6": lib32,
			},
			wantErr: ErrNotFound,
		},
		{
			name: "static binary",
			files: map[string]any{
				"/usr/bin/app":     elfSpec{typ: elf.ET_EXEC},
				"/lib64/libc.so.6": lib64,
			},
			wantErr: ErrStaticBinary,
		},
		{
			name: "musl binary",
			files: map[string]any{
				"/usr/bin/app":   elfSpec{interp: "/lib/ld-musl-x86_64.so.1", needed: []string{"libc.musl-x86_64.so.1"}},
				"/lib/libc.so.6": lib64,
			},
			wantErr: ErrMusl,
		},
		{
			name: "transitive dependency",
			files: map[string]any{
				"/usr/bin/app":     exe("libfoo.so.1"),
				"/lib64/libc.so.6": lib64,
			},
			wantErr: ErrNotNeeded,
		},
		{
			name:    "missing binary",
			files:   map[string]any{},
			wantErr: os.ErrNotExist,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := rootfs(t, tt.files)
			binary := tt.binary
			if binary == "" {
				binary = "/usr/bin/app"
			}
			soname := tt.soname
			if soname == "" {
				soname = libc
			}

			got, f, err := ResolveNeeded(root, binary, soname)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				require.Nil(t, f)
				return
			}
			require.NoError(t, err)
			defer f.Close()
			require.Equal(t, tt.want, got)

			// The returned file is the resolved library.
			want, err := root.Open(got)
			require.NoError(t, err)
			defer want.Close()
			fi, err := f.Stat()
			require.NoError(t, err)
			wantFi, err := want.Stat()
			require.NoError(t, err)
			require.True(t, os.SameFile(fi, wantFi))
		})
	}
}

func TestExpandTokens(t *testing.T) {
	parse := func(s elfSpec) *telf.SafeELFFile {
		f, err := telf.NewSafeELFFile(bytes.NewReader(s.bytes()))
		require.NoError(t, err)
		return f
	}
	x86 := parse(lib64)
	i386 := parse(elfSpec{class: elf.ELFCLASS32, machine: elf.EM_386})

	tests := []struct {
		dir    string
		origin string
		ef     *telf.SafeELFFile
		want   []string
	}{
		{dir: "/usr/lib", want: []string{"/usr/lib"}},
		{dir: "$ORIGIN/../lib", origin: "/opt/app/bin", want: []string{"/opt/app/bin/../lib"}},
		{dir: "${ORIGIN}/lib", origin: "/opt", want: []string{"/opt/lib"}},
		{dir: "$ORIGIN", origin: "/opt", want: []string{"/opt"}},
		{dir: "$ORIGIN/lib", want: nil}, // unknown origin
		{dir: "/opt/$LIB", want: []string{"/opt/lib/x86_64-linux-gnu", "/opt/lib64", "/opt/lib"}},
		{dir: "/opt/$LIB", ef: i386, want: []string{"/opt/lib/i386-linux-gnu", "/opt/lib"}},
		{dir: "/opt/$PLATFORM/lib", want: []string{"/opt/x86_64/lib"}},
		{dir: "/opt/$PLATFORM/lib", ef: i386, want: nil},
		{
			dir:    "$ORIGIN/${LIB}/$PLATFORM",
			origin: "/o",
			want:   []string{"/o/lib/x86_64-linux-gnu/x86_64", "/o/lib64/x86_64", "/o/lib/x86_64"},
		},
		{dir: "/opt/$UNKNOWN", want: nil},
		{dir: "/opt/${ORIGIN", origin: "/o", want: nil},
		{dir: "/opt/$", want: nil},
	}
	for _, tt := range tests {
		ef := tt.ef
		if ef == nil {
			ef = x86
		}
		require.Equal(t, tt.want, expandTokens(tt.dir, tt.origin, ef), "dir=%q origin=%q", tt.dir, tt.origin)
	}
}

// lddResolve returns the path ldd reports for soname, if any.
func lddResolve(t *testing.T, binary, soname string) string {
	t.Helper()
	out, err := exec.Command("ldd", binary).Output()
	if err != nil {
		t.Skipf("ldd %s failed: %v", binary, err)
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		name, rest, ok := strings.Cut(strings.TrimSpace(sc.Text()), " => ")
		if ok && name == soname {
			return strings.Fields(rest)[0]
		}
	}
	return ""
}

// TestResolveNeededHost checks we agree with ldd on host binaries.
func TestResolveNeededHost(t *testing.T) {
	if _, err := exec.LookPath("ldd"); err != nil {
		t.Skip("ldd not available")
	}

	binaries := []string{
		testutils.RepoRootPath("contrib/tester-progs/uprobe-simple"),
		"/bin/sh",
		"/usr/bin/env",
	}
	for _, binary := range binaries {
		t.Run(binary, func(t *testing.T) {
			if _, err := os.Stat(binary); err != nil {
				t.Skipf("%s not available", binary)
			}
			want := lddResolve(t, binary, "libc.so.6")
			if want == "" {
				t.Skipf("%s does not link libc.so.6", binary)
			}

			got, f, err := ResolveNeeded(HostRoot(), binary, "libc.so.6")
			require.NoError(t, err)
			defer f.Close()

			gotFi, err := os.Stat(got)
			require.NoError(t, err)
			wantFi, err := os.Stat(want)
			require.NoError(t, err)
			require.True(t, os.SameFile(gotFi, wantFi), "got %q, ldd says %q", got, want)
		})
	}
}
