// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package certloader

import (
	"context"
	"path/filepath"
	"slices"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
)

// watchInterval backstops the fsnotify events with a poll, covering both a
// missed event and lazy bootstrap, when the TLS files are written after the
// agent starts (e.g. cert-manager / cilium-certgen).
const watchInterval = 5 * time.Second

// Watch starts a background watcher that reloads r whenever any of its TLS
// files change on disk. Runs until ctx is canceled; failures are logged.
func Watch(ctx context.Context, r *Reloader) {
	go watch(ctx, r)
}

func watch(ctx context.Context, r *Reloader) {
	log := logger.GetLogger().With("component", "certloader")
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		log.Error("failed to create file watcher, TLS material will not be reloaded", logfields.Error, err)
		return
	}
	defer fsw.Close()

	ticker := time.NewTicker(watchInterval)
	defer ticker.Stop()

	// Watch parent directories: atomic rotations (rename into place,
	// Kubernetes Secret ..data swap) replace the inode and drop a file
	// watch.
	var dirs []string
	for _, f := range append([]string{r.cfg.CertFile, r.cfg.KeyFile}, r.cfg.ClientCAFiles...) {
		dirs = append(dirs, filepath.Dir(f))
	}
	slices.Sort(dirs)
	dirs = slices.Compact(dirs)

	// A directory a provisioner has yet to create cannot be watched, so
	// retry until Add succeeds.
	pending := slices.Clone(dirs)
	for {
		pending = slices.DeleteFunc(pending, func(d string) bool {
			return fsw.Add(d) == nil
		})
		if changed, err := r.reloadIfChanged(); err != nil {
			// Expected while the files are missing or mid-rotation;
			// the next event or tick retries.
			log.Warn("TLS material reload failed, retrying", logfields.Error, err)
		} else if changed {
			log.Info("TLS material reloaded")
		}

		select {
		case <-ctx.Done():
			return
		case ev := <-fsw.Events:
			// Removing a watched directory drops its watch.
			if ev.Has(fsnotify.Remove|fsnotify.Rename) && slices.Contains(dirs, ev.Name) &&
				!slices.Contains(pending, ev.Name) {
				pending = append(pending, ev.Name)
			}
		case err := <-fsw.Errors:
			log.Warn("TLS file watch error", logfields.Error, err)
		case <-ticker.C:
		}
	}
}
