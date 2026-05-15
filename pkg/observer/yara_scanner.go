// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux

package observer

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	yara "github.com/hillu/go-yara/v4"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
)

const (
	// yaraScanQueueSize is the max number of pending scan requests.
	// Non-blocking sends mean a full queue silently drops new requests rather
	// than stalling the eBPF ring-buffer dispatch loop.
	yaraScanQueueSize = 256

	// yaraWorkerCount is the number of goroutines consuming the scan queue.
	// Each worker owns one *yara.Scanner (Scanner is not goroutine-safe;
	// *yara.Rules is read-only after compilation and is shared safely).
	yaraWorkerCount = 4

	yaraScanTimeout = 5 * time.Second
)

type yaraScanRequest struct {
	pid  uint32
	path string
}

type yaraEngine struct {
	rules *yara.Rules
	queue chan yaraScanRequest
}

var (
	globalYaraEngine *yaraEngine
	yaraInitOnce     sync.Once

	// killFunc sends a signal to a process. Overridable in tests.
	killFunc = func(pid int, sig int) error {
		return syscall.Kill(pid, syscall.Signal(sig))
	}
)

// InitYaraScanner loads all .yar files from rulesDir and starts the worker pool.
// sync.Once guarantees the engine is initialised exactly once regardless of how
// many goroutines call this concurrently.
func InitYaraScanner(rulesDir string) error {
	var initErr error
	yaraInitOnce.Do(func() {
		initErr = initYaraEngine(rulesDir)
	})
	return initErr
}

func initYaraEngine(rulesDir string) error {
	compiler, err := yara.NewCompiler()
	if err != nil {
		return fmt.Errorf("yara: create compiler: %w", err)
	}

	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		return fmt.Errorf("yara: read rules dir %q: %w", rulesDir, err)
	}

	loaded := 0
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yar" {
			continue
		}
		ruleFile := filepath.Join(rulesDir, entry.Name())
		f, openErr := os.Open(ruleFile)
		if openErr != nil {
			logger.GetLogger().Warn("yara: skipping rule file", "file", ruleFile, logfields.Error, openErr)
			continue
		}
		if addErr := compiler.AddFile(f, ""); addErr != nil {
			logger.GetLogger().Warn("yara: compile error", "file", ruleFile, logfields.Error, addErr)
		} else {
			loaded++
		}
		f.Close()
	}

	if loaded == 0 {
		return fmt.Errorf("yara: no valid .yar files found in %q", rulesDir)
	}

	rules, err := compiler.GetRules()
	if err != nil {
		return fmt.Errorf("yara: get rules: %w", err)
	}

	eng := &yaraEngine{
		rules: rules,
		queue: make(chan yaraScanRequest, yaraScanQueueSize),
	}

	for i := range yaraWorkerCount {
		go eng.worker(i)
	}

	globalYaraEngine = eng
	logger.GetLogger().Info("yara: engine initialized", "rules_dir", rulesDir, "files_loaded", loaded)
	return nil
}

// enqueueYaraScan sends a scan request to the worker pool without blocking.
// If the queue is full the request is dropped — fail-safe: the eBPF ring-buffer
// dispatch loop must never block waiting for a userspace scan.
func enqueueYaraScan(pid uint32, path string) {
	if globalYaraEngine == nil {
		return
	}
	select {
	case globalYaraEngine.queue <- yaraScanRequest{pid: pid, path: path}:
	default:
		logger.GetLogger().Debug("yara: scan queue full, dropping request", "binary", path)
	}
}

func (e *yaraEngine) worker(id int) {
	// Each worker creates its own Scanner from the shared (immutable) *Rules.
	// yara.Scanner holds mutable callback/context state and is not goroutine-safe.
	sc, err := yara.NewScanner(e.rules)
	if err != nil {
		logger.GetLogger().Warn("yara: worker failed to create scanner", "worker_id", id, logfields.Error, err)
		return
	}
	sc.SetTimeout(yaraScanTimeout)

	for req := range e.queue {
		e.scan(sc, req)
	}
}

func (e *yaraEngine) scan(sc *yara.Scanner, req yaraScanRequest) {
	// Recover from any panic so a malformed binary or buggy YARA rule cannot
	// crash the worker goroutine and silently stop all future scans.
	defer func() {
		if r := recover(); r != nil {
			logger.GetLogger().Warn("yara: scan panic recovered", "binary", req.path, "panic", r)
		}
	}()

	var matches yara.MatchRules
	sc.SetCallback(&matches)
	if err := sc.ScanFile(req.path); err != nil {
		// The binary may have been replaced or unlinked between execve and scan.
		logger.GetLogger().Debug("yara: scan error (file may be gone)", "binary", req.path, logfields.Error, err)
		return
	}

	if len(matches) == 0 {
		return
	}

	names := make([]string, 0, len(matches))
	for _, m := range matches {
		names = append(names, m.Rule)
	}

	logger.GetLogger().Warn("yara: THREAT DETECTED — sending SIGKILL",
		"pid", req.pid,
		"binary", req.path,
		"matched_rules", names,
	)

	if err := killFunc(int(req.pid), int(syscall.SIGKILL)); err != nil {
		logger.GetLogger().Warn("yara: SIGKILL failed", "pid", req.pid, logfields.Error, err)
	}
}
