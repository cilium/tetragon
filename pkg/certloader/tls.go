// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package certloader

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
)

// Config drives a server-side TLS configuration. Zero values disable TLS.
type Config struct {
	// CertFile is a PEM-encoded server cert (leaf + optional intermediates).
	CertFile string
	// KeyFile is the PEM-encoded private key for CertFile.
	KeyFile string
	// ClientCAFiles is a list of PEM CA bundles used to verify client
	// certs. Required when RequireClientCert is true.
	ClientCAFiles []string
	// RequireClientCert toggles mTLS (RequireAndVerifyClientCert).
	RequireClientCert bool
}

// Enabled reports whether a server cert is configured.
func (c Config) Enabled() bool {
	return c.CertFile != "" && c.KeyFile != ""
}

// Validate enforces flag-layer invariants so callers can construct a
// Reloader without going through viper.
func (c Config) Validate() error {
	if c.CertFile == "" && c.KeyFile == "" && !c.RequireClientCert && len(c.ClientCAFiles) == 0 {
		return nil
	}
	if c.CertFile == "" || c.KeyFile == "" {
		return errors.New("server cert-file and key-file must be provided together")
	}
	if c.RequireClientCert && len(c.ClientCAFiles) == 0 {
		return errors.New("require-client-cert demands at least one client CA bundle")
	}
	if !c.RequireClientCert && len(c.ClientCAFiles) > 0 {
		return errors.New("client CA bundle is only honored when require-client-cert is true")
	}
	return nil
}

// Reloader holds TLS material and atomically swaps it on Reload, so a
// rotation does not interrupt in-flight handshakes. Safe for concurrent use.
type Reloader struct {
	cfg     Config
	snap    atomic.Pointer[snapshot]
	tlsConf *tls.Config

	// reloadMu serializes Reload so a slow read cannot overwrite a newer
	// snapshot and roll the listener back to stale material.
	reloadMu sync.Mutex
}

type snapshot struct {
	cert    *tls.Certificate
	caPool  *x509.CertPool
	require bool
}

// NewReloader loads the cert material described by cfg. The TLS files must
// exist on disk; use [NewReloaderLazy] when material is provisioned out of
// band (cert-manager, cilium-certgen) and may not be present at startup.
func NewReloader(cfg Config) (*Reloader, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if !cfg.Enabled() {
		return nil, errors.New("TLS is not enabled: server cert and key are required")
	}
	r := &Reloader{cfg: cfg}
	if err := r.Reload(); err != nil {
		return nil, err
	}
	r.tlsConf = r.buildTLSConfig()
	return r, nil
}

// NewReloaderLazy constructs a Reloader without requiring the TLS material
// to exist on disk. Handshakes performed before the first successful Reload
// fail with "certloader: no certificate loaded"; pair with [Watch] so the first
// reload happens automatically once the files appear.
//
// Use this when the agent may start before its provisioner (cert-manager,
// cilium-certgen Job) has written the Secret.
func NewReloaderLazy(cfg Config) (*Reloader, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if !cfg.Enabled() {
		return nil, errors.New("TLS is not enabled: server cert and key are required")
	}
	r := &Reloader{cfg: cfg}
	r.tlsConf = r.buildTLSConfig()
	_ = r.Reload() // best-effort; absence is recovered by Watch when files appear.
	return r, nil
}

// Ready reports whether a Reload has succeeded at least once. A Reloader
// returned by [NewReloader] is always Ready; one returned by [NewReloaderLazy]
// becomes Ready after [Watch] observes the TLS files on disk.
func (r *Reloader) Ready() bool {
	return r.snap.Load() != nil
}

// Reload re-reads the cert/key and CA bundle from disk and atomically
// replaces the active snapshot. Concurrent calls are serialized by reloadMu.
func (r *Reloader) Reload() error {
	r.reloadMu.Lock()
	defer r.reloadMu.Unlock()
	cert, err := tls.LoadX509KeyPair(r.cfg.CertFile, r.cfg.KeyFile)
	if err != nil {
		return fmt.Errorf("loading server cert/key: %w", err)
	}
	var pool *x509.CertPool
	if r.cfg.RequireClientCert {
		pool = x509.NewCertPool()
		for _, p := range r.cfg.ClientCAFiles {
			pem, err := os.ReadFile(p)
			if err != nil {
				return fmt.Errorf("reading client CA bundle %q: %w", p, err)
			}
			if !pool.AppendCertsFromPEM(pem) {
				return fmt.Errorf("client CA bundle %q contained no valid PEM certificates", p)
			}
		}
	}
	r.snap.Store(&snapshot{
		cert:    &cert,
		caPool:  pool,
		require: r.cfg.RequireClientCert,
	})
	return nil
}

// ServerConfig returns a [tls.Config] suitable for [credentials.NewTLS].
// The returned value is stable across reloads.
func (r *Reloader) ServerConfig() *tls.Config {
	return r.tlsConf
}

func (r *Reloader) buildTLSConfig() *tls.Config {
	// GetConfigForClient pins the snapshot (cert + CA pool) once per
	// handshake to avoid split-brain if a Reload lands mid-handshake.
	// The parent-config GetCertificate is unreachable when the server
	// uses GetConfigForClient; it's kept for non-server callers and tests.
	parentGetCert := func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
		s := r.snap.Load()
		if s == nil || s.cert == nil {
			return nil, errors.New("certloader: no certificate loaded")
		}
		return s.cert, nil
	}
	return &tls.Config{
		MinVersion:     tls.VersionTLS13,
		GetCertificate: parentGetCert,
		GetConfigForClient: func(_ *tls.ClientHelloInfo) (*tls.Config, error) {
			s := r.snap.Load()
			if s == nil || s.cert == nil {
				return nil, errors.New("certloader: no certificate loaded")
			}
			cert := s.cert
			caPool := s.caPool
			require := s.require
			out := &tls.Config{
				MinVersion: tls.VersionTLS13,
				GetCertificate: func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
					return cert, nil
				},
			}
			if require {
				out.ClientCAs = caPool
				out.ClientAuth = tls.RequireAndVerifyClientCert
			}
			return out, nil
		},
	}
}
