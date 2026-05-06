// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package grpctls_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/tests/e2e/flags"
	"github.com/cilium/tetragon/tests/e2e/helpers"
	tetragoninstall "github.com/cilium/tetragon/tests/e2e/install/tetragon"
	"github.com/cilium/tetragon/tests/e2e/runners"
	"github.com/cilium/tetragon/tests/e2e/state"
)

const agentTCPPort = 54321

var runner *runners.Runner

// TestMain installs Tetragon with mTLS via the helm method. The runner's
// default plaintext auto port-forward is skipped because it would fail
// the handshake against a TLS-required listener.
func TestMain(m *testing.M) {
	runner = runners.NewRunner().
		NoPortForward().
		WithInstallTetragon(tetragoninstall.WithHelmOptions(map[string]string{
			"tetragon.grpc.tls.enabled":           "true",
			"tetragon.grpc.tls.requireClientCert": "true",
			"tetragon.grpc.tls.auto.method":       "helm",
		})).
		Init()
	runner.Run(m)
}

// agentCerts loads the chart-provisioned trust root, CA cert, and CA
// private key (the latter is needed to mint a client cert in-test).
func agentCerts(ctx context.Context, t *testing.T, cfg *envconf.Config) (rootCAs *x509.CertPool, caCert *x509.Certificate, caKey crypto.Signer) {
	t.Helper()
	opts, ok := ctx.Value(state.InstallOpts).(*flags.HelmOptions)
	require.True(t, ok, "Tetragon install opts not in context")

	client, err := cfg.NewClient()
	require.NoError(t, err)
	r := client.Resources(opts.Namespace)

	serverSecret := corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: opts.DaemonSetName + "-server-certs", Namespace: opts.Namespace}}
	require.NoError(t, r.Get(ctx, serverSecret.Name, opts.Namespace, &serverSecret))

	caSecret := corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: opts.DaemonSetName + "-ca", Namespace: opts.Namespace}}
	require.NoError(t, r.Get(ctx, caSecret.Name, opts.Namespace, &caSecret))

	rootCAs = x509.NewCertPool()
	require.True(t, rootCAs.AppendCertsFromPEM(serverSecret.Data["ca.crt"]), "server-certs Secret has no usable ca.crt")

	caBlock, _ := pem.Decode(caSecret.Data["ca.crt"])
	require.NotNil(t, caBlock, "ca Secret missing ca.crt PEM")
	caCert, err = x509.ParseCertificate(caBlock.Bytes)
	require.NoError(t, err)

	keyBlock, _ := pem.Decode(caSecret.Data["ca.key"])
	require.NotNil(t, keyBlock, "ca Secret missing ca.key PEM")
	caKey, err = parsePrivateKey(keyBlock.Bytes)
	require.NoError(t, err)
	return rootCAs, caCert, caKey
}

// parsePrivateKey accepts the three PEM private-key encodings the
// chart's provisioning methods may produce: PKCS#8 (any algorithm),
// PKCS#1 (sprig genCA's RSA default), and SEC1 (EC).
func parsePrivateKey(der []byte) (crypto.Signer, error) {
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		signer, ok := k.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("PKCS#8 key is not a crypto.Signer (%T)", k)
		}
		return signer, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	return nil, errors.New("unrecognized private key format (tried PKCS#8, PKCS#1, SEC1)")
}

// mintClientCert produces a tls.Certificate signed by the supplied CA.
// The leaf key is RSA so the resulting tls.Certificate is usable
// regardless of the CA key's algorithm.
func mintClientCert(t *testing.T, caCert *x509.Certificate, caKey crypto.Signer) tls.Certificate {
	t.Helper()
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "tetragon-e2e-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: leafKey}
}

// portForwardAgent forwards the first Tetragon pod's TCP gRPC port to
// an OS-assigned loopback port and returns the local address.
func portForwardAgent(ctx context.Context, t *testing.T, cfg *envconf.Config) string {
	t.Helper()
	opts, ok := ctx.Value(state.InstallOpts).(*flags.HelmOptions)
	require.True(t, ok)
	client, err := cfg.NewClient()
	require.NoError(t, err)

	pods := &corev1.PodList{}
	require.NoError(t, client.Resources(opts.Namespace).List(ctx, pods,
		resources.WithLabelSelector("app.kubernetes.io/name="+opts.DaemonSetName)))
	require.NotEmpty(t, pods.Items, "no Tetragon pods found")
	pod := pods.Items[0]

	localPort := freeLoopbackPort(t)
	_, err = helpers.PortForwardPod(
		runner.Environment, &pod, nil, nil, 30, time.Second,
		func() error {
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", localPort), 2*time.Second)
			if err != nil {
				return err
			}
			_ = conn.Close()
			return nil
		},
		fmt.Sprintf("%d:%d", localPort, agentTCPPort),
	)(ctx, cfg)
	require.NoError(t, err, "could not establish port-forward")
	return fmt.Sprintf("127.0.0.1:%d", localPort)
}

// freeLoopbackPort asks the kernel for an unused loopback port. The
// returned port is closed before use, so a TOCTOU race is possible but
// far smaller than any fixed-range counter under matrix parallelism.
func freeLoopbackPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())
	return port
}

func dial(t *testing.T, addr string, creds credentials.TransportCredentials) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func rpcContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// validClientCreds builds the valid-client-cert mTLS credentials reused
// by the readiness probe and the happy-path assertion.
func validClientCreds(t *testing.T, rootCAs *x509.CertPool, caCert *x509.Certificate, caKey crypto.Signer) credentials.TransportCredentials {
	t.Helper()
	return credentials.NewTLS(&tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      rootCAs,
		Certificates: []tls.Certificate{mintClientCert(t, caCert, caKey)},
		ServerName:   "any.tetragon-grpc.cilium.io",
	})
}

// waitForReady blocks until a valid mTLS dial + GetVersion succeeds.
// Pod readiness only gates on the liveness probe (port 6789); the main
// gRPC listener comes up later, after BPF setup. Without this probe a
// rejection test can pass spuriously by dialling before the listener
// exists (codes.Unavailable from "connection refused" is
// indistinguishable from a TLS reject).
func waitForReady(t *testing.T, addr string, creds credentials.TransportCredentials) string {
	t.Helper()
	var version string
	require.Eventually(t, func() bool {
		conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
		if err != nil {
			return false
		}
		defer func() { _ = conn.Close() }()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		resp, err := tetragon.NewFineGuidanceSensorsClient(conn).
			GetVersion(ctx, &tetragon.GetVersionRequest{})
		if err != nil || resp.GetVersion() == "" {
			return false
		}
		version = resp.GetVersion()
		return true
	}, 90*time.Second, time.Second, "agent gRPC listener not ready")
	return version
}

func TestMTLSHandshake(t *testing.T) {
	feature := features.New("mTLS handshake succeeds with valid client cert").
		Assess("GetVersion", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			rootCAs, caCert, caKey := agentCerts(ctx, t, cfg)
			addr := portForwardAgent(ctx, t, cfg)
			version := waitForReady(t, addr, validClientCreds(t, rootCAs, caCert, caKey))
			t.Logf("handshake succeeded, agent version: %s", version)
			return ctx
		}).Feature()
	runner.Test(t, feature)
}

func TestMTLSRejectsPlaintext(t *testing.T) {
	feature := features.New("mTLS rejects plaintext clients").
		Assess("dial fails", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			rootCAs, caCert, caKey := agentCerts(ctx, t, cfg)
			addr := portForwardAgent(ctx, t, cfg)
			waitForReady(t, addr, validClientCreds(t, rootCAs, caCert, caKey))

			conn := dial(t, addr, insecure.NewCredentials())
			_, err := tetragon.NewFineGuidanceSensorsClient(conn).
				GetVersion(rpcContext(t), &tetragon.GetVersionRequest{})
			requireUnavailable(t, err)
			t.Logf("rejected plaintext client: %s", err)
			return ctx
		}).Feature()
	runner.Test(t, feature)
}

func TestMTLSRejectsAnonymousTLS(t *testing.T) {
	feature := features.New("mTLS rejects clients without a client cert").
		Assess("dial fails", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			rootCAs, caCert, caKey := agentCerts(ctx, t, cfg)
			addr := portForwardAgent(ctx, t, cfg)
			waitForReady(t, addr, validClientCreds(t, rootCAs, caCert, caKey))

			creds := credentials.NewTLS(&tls.Config{
				MinVersion: tls.VersionTLS13,
				RootCAs:    rootCAs,
				ServerName: "any.tetragon-grpc.cilium.io",
			})
			conn := dial(t, addr, creds)
			_, err := tetragon.NewFineGuidanceSensorsClient(conn).
				GetVersion(rpcContext(t), &tetragon.GetVersionRequest{})
			requireUnavailable(t, err)
			t.Logf("handshake rejected as expected with client TLS but no cert: %s", err)
			return ctx
		}).Feature()
	runner.Test(t, feature)
}

// requireUnavailable asserts the RPC failed with codes.Unavailable.
// gRPC wraps both rejected handshakes and post-handshake resets that
// way. A raw timeout is treated as a failure rather than a rejection
// signal so a slow CI node cannot mask an absent server-side reject.
func requireUnavailable(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	s, ok := status.FromError(err)
	require.True(t, ok, "expected a gRPC status error, got: %v", err)
	require.Equal(t, codes.Unavailable, s.Code(),
		"expected Unavailable, got %v: %s", s.Code(), s.Message())
}
