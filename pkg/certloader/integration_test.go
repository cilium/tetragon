// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package certloader_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	healthgrpc "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/cilium/tetragon/pkg/certloader"
)

const dialTimeout = 5 * time.Second

type stubHealth struct {
	healthgrpc.UnimplementedHealthServer
}

func (stubHealth) Check(_ context.Context, _ *healthgrpc.HealthCheckRequest) (*healthgrpc.HealthCheckResponse, error) {
	return &healthgrpc.HealthCheckResponse{Status: healthgrpc.HealthCheckResponse_SERVING}, nil
}

// startServer registers a Health stub on a TLS-wrapped listener and blocks
// teardown on the Serve goroutine to surface errors deterministically.
func startServer(t *testing.T, creds credentials.TransportCredentials) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := grpc.NewServer(grpc.Creds(creds))
	healthgrpc.RegisterHealthServer(srv, stubHealth{})
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(lis) }()
	t.Cleanup(func() {
		srv.Stop()
		_ = lis.Close()
		if err := <-serveErr; err != nil {
			t.Errorf("grpc Serve returned: %v", err)
		}
	})
	return lis.Addr().String()
}

func rootPool(t *testing.T, pki *certloader.TestPKI) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	caPEM, err := os.ReadFile(pki.CACertPath)
	require.NoError(t, err)
	require.True(t, pool.AppendCertsFromPEM(caPEM))
	return pool
}

func loadKeyPair(t *testing.T, certPath, keyPath string) tls.Certificate {
	t.Helper()
	c, err := tls.LoadX509KeyPair(certPath, keyPath)
	require.NoError(t, err)
	return c
}

func setupServer(t *testing.T, mtls bool) (*certloader.TestPKI, string) {
	t.Helper()
	dir := t.TempDir()
	pki, err := certloader.NewTestPKI(dir)
	require.NoError(t, err)
	server, err := pki.Issue(dir, certloader.IssueOpts{
		CommonName: "server",
		DNSNames:   []string{"localhost"},
		IPs:        []net.IP{net.ParseIP("127.0.0.1")},
		IsServer:   true,
	})
	require.NoError(t, err)
	cfg := certloader.Config{CertFile: server.CertPath, KeyFile: server.KeyPath}
	if mtls {
		cfg.RequireClientCert = true
		cfg.ClientCAFiles = []string{pki.CACertPath}
	}
	r, err := certloader.NewReloader(cfg)
	require.NoError(t, err)
	return pki, startServer(t, credentials.NewTLS(r.ServerConfig()))
}

// dialContext returns a context bounded by the test deadline (or
// dialTimeout, whichever is shorter) and registers the cancel.
func dialContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), dialTimeout)
	t.Cleanup(cancel)
	return ctx
}

func TestMTLSValidClient(t *testing.T) {
	t.Parallel()
	pki, addr := setupServer(t, true)
	clientLeaf, err := pki.Issue(t.TempDir(), certloader.IssueOpts{CommonName: "client"})
	require.NoError(t, err)
	clientCert := loadKeyPair(t, clientLeaf.CertPath, clientLeaf.KeyPath)

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      rootPool(t, pki),
		Certificates: []tls.Certificate{clientCert},
		ServerName:   "localhost",
	})))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	resp, err := healthgrpc.NewHealthClient(conn).Check(dialContext(t), &healthgrpc.HealthCheckRequest{})
	require.NoError(t, err)
	assert.Equal(t, healthgrpc.HealthCheckResponse_SERVING, resp.Status)
}

func TestMTLSRejectsClientWithoutCert(t *testing.T) {
	t.Parallel()
	pki, addr := setupServer(t, true)

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    rootPool(t, pki),
		ServerName: "localhost",
	})))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	_, err = healthgrpc.NewHealthClient(conn).Check(dialContext(t), &healthgrpc.HealthCheckRequest{})
	require.Error(t, err)
}

func TestMTLSRejectsUntrustedClient(t *testing.T) {
	t.Parallel()
	pki, addr := setupServer(t, true)
	otherPKI, err := certloader.NewTestPKI(t.TempDir())
	require.NoError(t, err)
	rogue, err := otherPKI.Issue(t.TempDir(), certloader.IssueOpts{CommonName: "rogue"})
	require.NoError(t, err)
	rogueCert := loadKeyPair(t, rogue.CertPath, rogue.KeyPath)

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      rootPool(t, pki),
		Certificates: []tls.Certificate{rogueCert},
		ServerName:   "localhost",
	})))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	_, err = healthgrpc.NewHealthClient(conn).Check(dialContext(t), &healthgrpc.HealthCheckRequest{})
	require.Error(t, err)
}

func TestServerOnlyTLSAcceptsClientWithoutCert(t *testing.T) {
	t.Parallel()
	pki, addr := setupServer(t, false)

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    rootPool(t, pki),
		ServerName: "localhost",
	})))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	_, err = healthgrpc.NewHealthClient(conn).Check(dialContext(t), &healthgrpc.HealthCheckRequest{})
	require.NoError(t, err)
}

func TestServerOnlyTLSRejectsPlaintextClient(t *testing.T) {
	t.Parallel()
	_, addr := setupServer(t, false)

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	_, err = healthgrpc.NewHealthClient(conn).Check(dialContext(t), &healthgrpc.HealthCheckRequest{})
	require.Error(t, err)
}

// TestLazyReloaderRecoversWhenFilesAppear exercises the cert-manager /
// cilium-certgen bootstrap path: the agent starts pointing at TLS file paths
// that do not yet exist, the watcher observes their CREATE, and handshakes
// start succeeding without a server restart.
func TestLazyReloaderRecoversWhenFilesAppear(t *testing.T) {
	t.Parallel()

	mountDir := t.TempDir()
	certPath := filepath.Join(mountDir, "tls.crt")
	keyPath := filepath.Join(mountDir, "tls.key")

	pki, err := certloader.NewTestPKI(t.TempDir())
	require.NoError(t, err)
	issued, err := pki.Issue(t.TempDir(), certloader.IssueOpts{
		CommonName: "server",
		DNSNames:   []string{"localhost"},
		IPs:        []net.IP{net.ParseIP("127.0.0.1")},
		IsServer:   true,
	})
	require.NoError(t, err)

	r, err := certloader.NewReloaderLazy(certloader.Config{CertFile: certPath, KeyFile: keyPath})
	require.NoError(t, err)
	require.False(t, r.Ready(), "lazy reloader must not be ready before files exist")

	require.NoError(t, certloader.Watch(t.Context(), r))
	addr := startServer(t, credentials.NewTLS(r.ServerConfig()))

	dial := func() (*grpc.ClientConn, error) {
		return grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			MinVersion: tls.VersionTLS13,
			RootCAs:    rootPool(t, pki),
			ServerName: "localhost",
		})))
	}

	failConn, err := dial()
	require.NoError(t, err)
	t.Cleanup(func() { _ = failConn.Close() })
	_, err = healthgrpc.NewHealthClient(failConn).Check(dialContext(t), &healthgrpc.HealthCheckRequest{})
	require.Error(t, err, "handshake must fail before TLS material is provisioned")

	copyFile(t, issued.CertPath, certPath)
	copyFile(t, issued.KeyPath, keyPath)

	require.Eventually(t, func() bool {
		if !r.Ready() {
			return false
		}
		conn, err := dial()
		if err != nil {
			return false
		}
		defer conn.Close()
		_, err = healthgrpc.NewHealthClient(conn).Check(dialContext(t), &healthgrpc.HealthCheckRequest{})
		return err == nil
	}, 5*time.Second, 50*time.Millisecond)
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(dst, b, 0600))
}
