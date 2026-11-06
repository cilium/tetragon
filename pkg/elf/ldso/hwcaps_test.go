// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux

package ldso

import (
	"bufio"
	"bytes"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	telf "github.com/cilium/tetragon/pkg/elf"
)

// loaderHwcaps returns the glibc-hwcaps subdirectories the given glibc
// dynamic loader reports as searched, from its --help output.
func loaderHwcaps(t *testing.T, loader string) []string {
	t.Helper()
	out, err := exec.Command(loader, "--help").Output()
	if err != nil {
		t.Skipf("%s --help failed: %v", loader, err)
	}

	// e.g.:
	// Subdirectories of glibc-hwcaps directories, in priority order:
	//   x86-64-v4
	//   x86-64-v3 (supported, searched)
	//   x86-64-v2 (supported, searched)
	const header = "Subdirectories of glibc-hwcaps directories, in priority order:"
	_, section, ok := bytes.Cut(out, []byte(header))
	if !ok {
		t.Skipf("%s does not support glibc-hwcaps", loader)
	}
	subdirs := []string{}
	sc := bufio.NewScanner(bytes.NewReader(section))
	sc.Scan() // rest of the header line
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "  ") {
			break
		}
		name, flags, _ := strings.Cut(strings.TrimSpace(line), " ")
		if strings.Contains(flags, "searched") {
			subdirs = append(subdirs, name)
		}
	}
	return subdirs
}

// TestHostHwcaps checks we agree with the host dynamic loader on the
// glibc-hwcaps subdirectories to search.
func TestHostHwcaps(t *testing.T) {
	const binary = "/bin/sh"
	loader, f, err := ResolveInterpreter(HostRoot(), binary)
	if err != nil {
		t.Skipf("no interpreter for %s: %v", binary, err)
	}
	f.Close()

	ef, err := telf.OpenSafeELFFile(binary)
	require.NoError(t, err)
	defer ef.Close()

	want := loaderHwcaps(t, loader)
	got := hostHwcaps(ef.Machine, ef.Class)
	if got == nil {
		got = []string{}
	}
	require.Equal(t, want, got)
}
