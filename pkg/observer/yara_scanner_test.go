// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux

package observer

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// --- isTrustedBinary ---

func TestIsTrustedBinary_KnownSafePaths(t *testing.T) {
	safe := []string{
		"/bin/bash",
		"/sbin/init",
		"/usr/bin/python3",
		"/usr/sbin/sshd",
		"/usr/lib/systemd/systemd",
		"/usr/lib64/libc.so.6",
		"/lib/x86_64-linux-gnu/libc.so.6",
		"/lib64/ld-linux-x86-64.so.2",
		"/etc/alternatives/python",
		"/var/lib/snapd/snap/bin/code",
		"/snap/core/current/bin/bash",
		"/run/containerd/io.containerd.runtime.v2.task/moby/abc/rootfs/bin/sh",
		"/proc/self/exe",
		"/sys/fs/cgroup/init",
	}
	for _, path := range safe {
		if !isTrustedBinary(path) {
			t.Errorf("expected %q to be trusted, got untrusted", path)
		}
	}
}

func TestIsTrustedBinary_SuspectPaths(t *testing.T) {
	suspect := []string{
		"/tmp/malware",
		"/home/user/.local/bin/suspicious",
		"/dev/shm/payload",
		"/opt/ransomware",
		"/root/dropper",
		"",
		"relative/path",
	}
	for _, path := range suspect {
		if isTrustedBinary(path) {
			t.Errorf("expected %q to be untrusted, got trusted", path)
		}
	}
}

// --- InitYaraScanner ---

func TestInitYaraScanner_MissingDir(t *testing.T) {
	resetYaraEngine(t)
	err := InitYaraScanner("/nonexistent/yara/rules")
	if err == nil {
		t.Fatal("expected error for missing directory, got nil")
	}
}

func TestInitYaraScanner_EmptyDir(t *testing.T) {
	resetYaraEngine(t)
	dir := t.TempDir()
	err := InitYaraScanner(dir)
	if err == nil {
		t.Fatal("expected error for empty directory (no .yar files), got nil")
	}
}

func TestInitYaraScanner_InvalidRule(t *testing.T) {
	resetYaraEngine(t)
	dir := t.TempDir()
	// Write a syntactically broken rule
	writeRule(t, dir, "bad.yar", `rule Bad { strings: $x = "ok" condition: }`)
	err := InitYaraScanner(dir)
	// Compiler should fail on the broken rule; no valid rules loaded → error
	if err == nil {
		t.Fatal("expected error for invalid rule, got nil")
	}
}

func TestInitYaraScanner_ValidRule(t *testing.T) {
	resetYaraEngine(t)
	dir := t.TempDir()
	writeRule(t, dir, "test.yar", simpleRule("TestRule", "TETRAGON_TEST_MARKER"))
	if err := InitYaraScanner(dir); err != nil {
		t.Fatalf("InitYaraScanner with valid rule: %v", err)
	}
	if globalYaraEngine == nil {
		t.Fatal("globalYaraEngine is nil after successful init")
	}
}

func TestInitYaraScanner_IdempotentOnce(t *testing.T) {
	resetYaraEngine(t)
	dir := t.TempDir()
	writeRule(t, dir, "test.yar", simpleRule("TestRule", "MARKER"))

	var wg sync.WaitGroup
	errs := make([]error, 5)
	for i := range 5 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			errs[idx] = InitYaraScanner(dir)
		}(i)
	}
	wg.Wait()

	// sync.Once guarantees initYaraEngine runs exactly once.
	// All subsequent calls are no-ops and return nil (zero-value of initErr).
	// Invariant: no call panics, engine is initialised, all calls return nil.
	for i, err := range errs {
		if err != nil {
			t.Errorf("call %d: unexpected error: %v", i, err)
		}
	}
	if globalYaraEngine == nil {
		t.Error("globalYaraEngine is nil after concurrent inits")
	}
	if len(globalYaraEngine.queue) != 0 {
		t.Error("queue should be empty at startup")
	}
}

// --- enqueueYaraScan ---

func TestEnqueueYaraScan_NilEngine(t *testing.T) {
	resetYaraEngine(t)
	// Must not panic when engine is not initialised.
	enqueueYaraScan(1234, "/tmp/test")
}

func TestEnqueueYaraScan_QueueFull(t *testing.T) {
	resetYaraEngine(t)
	dir := t.TempDir()
	writeRule(t, dir, "test.yar", simpleRule("NeverMatch", "ZZZZ_NEVER_MATCH_ZZZZ"))
	if err := InitYaraScanner(dir); err != nil {
		t.Fatalf("init: %v", err)
	}
	// Fill the queue beyond its capacity — must not block or panic.
	for i := range yaraScanQueueSize + 10 {
		enqueueYaraScan(uint32(i), "/tmp/filler")
	}
}

// --- YARA scan matching ---

func TestYaraScan_Match(t *testing.T) {
	resetYaraEngine(t)
	dir := t.TempDir()
	marker := "TETRAGON_YARA_UNIQUE_MARKER_XYZ"
	writeRule(t, dir, "test.yar", simpleRule("MarkerRule", marker))

	if err := InitYaraScanner(dir); err != nil {
		t.Fatalf("init: %v", err)
	}

	// Write a "binary" that contains the marker string.
	target := filepath.Join(t.TempDir(), "fake_binary")
	if err := os.WriteFile(target, []byte("ELF_HEADER "+marker+" padding"), 0600); err != nil {
		t.Fatal(err)
	}

	matched := make(chan struct{}, 1)
	origKill := killFunc
	killFunc = func(pid int, _ int) error {
		matched <- struct{}{}
		return nil
	}
	defer func() { killFunc = origKill }()

	enqueueYaraScan(9999, target)

	select {
	case <-matched:
		// expected: SIGKILL was triggered
	case <-time.After(3 * time.Second):
		t.Error("SIGKILL not triggered within timeout for matching binary")
	}
}

func TestYaraScan_NoMatch(t *testing.T) {
	resetYaraEngine(t)
	dir := t.TempDir()
	writeRule(t, dir, "test.yar", simpleRule("NeverMatch", "ZZZZ_NEVER_MATCH_ZZZZ_9999"))

	if err := InitYaraScanner(dir); err != nil {
		t.Fatalf("init: %v", err)
	}

	target := filepath.Join(t.TempDir(), "clean_binary")
	if err := os.WriteFile(target, []byte("ELF clean binary no markers"), 0600); err != nil {
		t.Fatal(err)
	}

	killed := false
	origKill := killFunc
	killFunc = func(_ int, _ int) error {
		killed = true
		return nil
	}
	defer func() { killFunc = origKill }()

	enqueueYaraScan(1111, target)
	time.Sleep(500 * time.Millisecond)

	if killed {
		t.Error("SIGKILL triggered for a clean binary")
	}
}

func TestYaraScan_MissingFile(t *testing.T) {
	resetYaraEngine(t)
	dir := t.TempDir()
	writeRule(t, dir, "test.yar", simpleRule("AnyRule", "MARKER"))
	if err := InitYaraScanner(dir); err != nil {
		t.Fatalf("init: %v", err)
	}
	// Must not panic or block — file doesn't exist, should be silently skipped.
	enqueueYaraScan(5555, "/nonexistent/binary/path")
	time.Sleep(300 * time.Millisecond)
}

// --- helpers ---

// resetYaraEngine resets the singleton so each test starts fresh.
func resetYaraEngine(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		globalYaraEngine = nil
		yaraInitOnce = sync.Once{}
	})
	globalYaraEngine = nil
	yaraInitOnce = sync.Once{}
}

func writeRule(t *testing.T, dir, filename, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, filename), []byte(content), 0600); err != nil {
		t.Fatalf("writeRule %s: %v", filename, err)
	}
}

func simpleRule(name, marker string) string {
	return `rule ` + name + ` {
    strings:
        $m = "` + marker + `"
    condition:
        $m
}`
}
