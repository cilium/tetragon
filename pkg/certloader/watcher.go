// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package certloader

import (
	"context"
	"crypto/tls"
	"errors"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/certwatcher"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
)

// watchInterval polls cert/key as a safety net for fsnotify events missed
// during atomic rotations (notably Kubernetes Secret ..data symlink swaps,
// which file-level fsnotify cannot observe).
const watchInterval = 5 * time.Second

// retryInterval governs construction retries during lazy bootstrap (cert
// files written after the agent starts, e.g. cert-manager / cilium-certgen).
const retryInterval = 5 * time.Second

// Watch starts a background watcher that calls r.Reload whenever the cert or
// key change on disk. Reload re-reads the client CA bundle too, so all TLS
// material stays in sync. Runs until ctx is canceled; failures are logged.
func Watch(ctx context.Context, r *Reloader) {
	log := logger.GetLogger().With("component", "certloader")
	go func() {
		cw, err := waitForCertWatcher(ctx, r.cfg.CertFile, r.cfg.KeyFile)
		if err != nil {
			return
		}
		// RegisterCallback fires once immediately, promoting a lazy
		// Reloader to Ready as soon as the cert can be loaded.
		cw.RegisterCallback(func(_ tls.Certificate) {
			if err := r.Reload(); err != nil {
				log.Error("TLS reload failed", logfields.Error, err)
				return
			}
			log.Info("TLS material reloaded")
		})
		if err := cw.Start(ctx); err != nil && !errors.Is(err, context.Canceled) {
			log.Error("certwatcher exited", logfields.Error, err)
		}
	}()
}

// waitForCertWatcher retries certwatcher.New until it succeeds or ctx is
// canceled. Construction can fail for missing files, mid-rotation cert/key
// mismatch, bad permissions, or malformed PEM — all retried so a transient
// bootstrap race does not crash the agent. Errors are logged so a permanent
// misconfiguration is visible instead of silently spinning.
func waitForCertWatcher(ctx context.Context, certPath, keyPath string) (*certwatcher.CertWatcher, error) {
	log := logger.GetLogger().With("component", "certloader")
	timer := time.NewTimer(retryInterval)
	defer timer.Stop()
	for {
		cw, err := certwatcher.New(certPath, keyPath)
		if err == nil {
			return cw.WithWatchInterval(watchInterval), nil
		}
		log.Warn("certwatcher init failed; retrying", logfields.Error, err)
		timer.Reset(retryInterval)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}
