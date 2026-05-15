// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package certloader

import (
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigValidate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{name: "zero", cfg: Config{}},
		{name: "cert without key", cfg: Config{CertFile: "a"}, wantErr: true},
		{name: "key without cert", cfg: Config{KeyFile: "a"}, wantErr: true},
		{name: "tls only", cfg: Config{CertFile: "a", KeyFile: "b"}},
		{name: "mtls without ca", cfg: Config{CertFile: "a", KeyFile: "b", RequireClientCert: true}, wantErr: true},
		{name: "mtls ok", cfg: Config{CertFile: "a", KeyFile: "b", RequireClientCert: true, ClientCAFiles: []string{"c"}}},
		{name: "ca without mtls", cfg: Config{CertFile: "a", KeyFile: "b", ClientCAFiles: []string{"c"}}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.cfg.Validate()
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestNewReloaderRejectsDisabled(t *testing.T) {
	t.Parallel()
	_, err := NewReloader(Config{})
	require.Error(t, err)
}

// newServerReloader mints a fresh CA + server leaf and returns a Reloader.
func newServerReloader(t *testing.T, mtls bool) (*Reloader, *TestPKI, *LeafFiles) {
	t.Helper()
	dir := t.TempDir()
	pki, err := NewTestPKI(dir)
	require.NoError(t, err)
	srv, err := pki.Issue(dir, IssueOpts{
		CommonName: "server",
		DNSNames:   []string{"localhost"},
		IPs:        []net.IP{net.ParseIP("127.0.0.1")},
		IsServer:   true,
	})
	require.NoError(t, err)
	cfg := Config{CertFile: srv.CertPath, KeyFile: srv.KeyPath}
	if mtls {
		cfg.RequireClientCert = true
		cfg.ClientCAFiles = []string{pki.CACertPath}
	}
	r, err := NewReloader(cfg)
	require.NoError(t, err)
	return r, pki, srv
}

func TestNewReloaderLoadsCerts(t *testing.T) {
	t.Parallel()
	r, _, _ := newServerReloader(t, true)

	cert, pool, mtls := r.Snapshot()
	require.NotNil(t, cert)
	require.NotNil(t, pool)
	require.True(t, mtls)

	cfg := r.ServerConfig()
	assert.Equal(t, uint16(tls.VersionTLS13), cfg.MinVersion)

	clientCfg, err := cfg.GetConfigForClient(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	assert.Equal(t, tls.RequireAndVerifyClientCert, clientCfg.ClientAuth)
	assert.NotNil(t, clientCfg.ClientCAs)

	got, err := cfg.GetCertificate(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	require.NotNil(t, got)
}

func TestReloadPicksUpRotation(t *testing.T) {
	t.Parallel()
	r, pki, srv := newServerReloader(t, false)
	first, _, _ := r.Snapshot()

	srv2, err := pki.Issue(t.TempDir(), IssueOpts{CommonName: "server2", DNSNames: []string{"localhost"}, IsServer: true})
	require.NoError(t, err)
	mustCopy(t, srv2.CertPath, srv.CertPath)
	mustCopy(t, srv2.KeyPath, srv.KeyPath)

	require.NoError(t, r.Reload())
	second, _, _ := r.Snapshot()
	require.NotEmpty(t, first.Certificate)
	require.NotEmpty(t, second.Certificate)
	assert.NotEqual(t, string(first.Certificate[0]), string(second.Certificate[0]))
}

// TestReloadFailsOnBadKey asserts a failed Reload preserves the prior
// snapshot, so the server keeps serving stale-but-valid material.
func TestReloadFailsOnBadKey(t *testing.T) {
	t.Parallel()
	r, _, srv := newServerReloader(t, false)

	require.NoError(t, os.WriteFile(srv.KeyPath, []byte("not a key"), 0600))
	prev, _, _ := r.Snapshot()
	require.Error(t, r.Reload())
	cur, _, _ := r.Snapshot()
	assert.Equal(t, string(prev.Certificate[0]), string(cur.Certificate[0]))
}

func TestReloadFailsOnBadCABundle(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pki, err := NewTestPKI(dir)
	require.NoError(t, err)
	srv, err := pki.Issue(dir, IssueOpts{CommonName: "server", DNSNames: []string{"localhost"}, IsServer: true})
	require.NoError(t, err)

	bogus := filepath.Join(dir, "bogus-ca.pem")
	require.NoError(t, os.WriteFile(bogus, []byte("not pem\n"), 0600))

	_, err = NewReloader(Config{
		CertFile:          srv.CertPath,
		KeyFile:           srv.KeyPath,
		ClientCAFiles:     []string{bogus},
		RequireClientCert: true,
	})
	require.Error(t, err)
}

// TestReloadIsSerialized asserts concurrent Reload calls leave the snapshot
// reflecting the last completed disk read; a slow read returning after a
// faster one must not overwrite the newer snapshot.
func TestReloadIsSerialized(t *testing.T) {
	t.Parallel()
	r, _, srv := newServerReloader(t, false)

	const goroutines = 16
	const iterations = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			for range iterations {
				if err := r.Reload(); err != nil {
					t.Errorf("Reload: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()

	cert, _, _ := r.Snapshot()
	require.NotNil(t, cert)
	require.NotEmpty(t, cert.Certificate)

	want, err := tls.LoadX509KeyPair(srv.CertPath, srv.KeyPath)
	require.NoError(t, err)
	assert.Equal(t, string(want.Certificate[0]), string(cert.Certificate[0]))
}

func TestWatchTriggersReload(t *testing.T) {
	t.Parallel()
	r, pki, srv := newServerReloader(t, false)

	require.NoError(t, Watch(t.Context(), r))
	first, _, _ := r.Snapshot()

	srv2, err := pki.Issue(t.TempDir(), IssueOpts{CommonName: "server2", DNSNames: []string{"localhost"}, IsServer: true})
	require.NoError(t, err)
	mustCopy(t, srv2.CertPath, srv.CertPath)
	mustCopy(t, srv2.KeyPath, srv.KeyPath)

	// 5s tolerates the 250ms debounce plus fsnotify dispatch on loaded CI.
	require.Eventually(t, func() bool {
		cur, _, _ := r.Snapshot()
		return string(first.Certificate[0]) != string(cur.Certificate[0])
	}, 5*time.Second, 50*time.Millisecond)
}

func mustCopy(t *testing.T, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(dst, b, 0600))
}
