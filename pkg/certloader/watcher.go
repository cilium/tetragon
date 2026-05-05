// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package certloader

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
)

// debounceWindow coalesces fsnotify event bursts from atomic rotations.
const debounceWindow = 250 * time.Millisecond

// Watch reloads r whenever any of the configured TLS files change on disk.
// Parent directories are watched (not the files themselves) so atomic
// rename-based rotations (cert-manager, Kubernetes Secret projection) are
// observed. Paths are resolved to absolute form because fsnotify emits
// absolute event paths.
func Watch(ctx context.Context, r *Reloader) error {
	tracked, err := absolutePaths(r.cfg)
	if err != nil {
		return fmt.Errorf("certloader: resolving TLS paths: %w", err)
	}
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("certloader: creating fsnotify watcher: %w", err)
	}

	dirs := map[string]struct{}{}
	for _, p := range tracked {
		dirs[filepath.Dir(p)] = struct{}{}
	}
	for d := range dirs {
		if err := w.Add(d); err != nil {
			_ = w.Close()
			return fmt.Errorf("certloader: watching dir %q: %w", d, err)
		}
	}

	log := logger.GetLogger().With("component", "certloader.Watch")
	go run(ctx, w, tracked, log, r)
	return nil
}

// absolutePaths normalizes the configured TLS file paths to absolute form.
func absolutePaths(cfg Config) ([]string, error) {
	var out []string
	for _, p := range append([]string{cfg.CertFile, cfg.KeyFile}, cfg.ClientCAFiles...) {
		if p == "" {
			continue
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			return nil, err
		}
		out = append(out, abs)
	}
	return out, nil
}

// slogger is the subset of slog used here, fakeable in tests.
type slogger interface {
	Info(msg string, args ...any)
	Error(msg string, args ...any)
	Debug(msg string, args ...any)
}

// run debounces fsnotify event bursts (e.g. cert-manager / Secret
// projection rotations) into a single Reloader.Reload. Exits on
// ctx cancellation or when the fsnotify channels close.
func run(ctx context.Context, w *fsnotify.Watcher, tracked []string, log slogger, r *Reloader) {
	defer func() { _ = w.Close() }()

	timer := time.NewTimer(time.Hour)
	for {
		select {
		case <-ctx.Done():
			return

		case <-timer.C:
			// Debounce window elapsed: perform the actual reload.
			if err := r.Reload(); err != nil {
				log.Error("TLS reload failed", logfields.Error, err)
				continue
			}
			log.Info("TLS material reloaded")

		case ev, ok := <-w.Events:
			// fsnotify Events channel closed: watcher is gone, exit.
			if !ok {
				return
			}
			// Ignore unrelated paths; arm the debounce timer for ours.
			if triggersReload(ev, tracked) {
				log.Debug("TLS file change detected", "event", ev.String())
				timer.Reset(debounceWindow)
			}

		case err, ok := <-w.Errors:
			if !ok {
				return
			}
			// On queue overflow we may have missed a rotation; reconcile
			// by scheduling a reload so state converges with disk.
			log.Error("fsnotify watcher error, scheduling reconciliation reload", logfields.Error, err)
			timer.Reset(debounceWindow)
		}
	}
}

// triggersReload reports whether an fsnotify event concerns a file we must
// react to: a directly tracked TLS file, or the ..data symlink swapped
// atomically by Kubernetes Secret projection.
func triggersReload(ev fsnotify.Event, tracked []string) bool {
	if slices.Contains(tracked, filepath.Clean(ev.Name)) {
		return true
	}
	return filepath.Base(ev.Name) == "..data"
}
