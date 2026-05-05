// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package common

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestTLSConfigEnabled(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		cfg  TLSConfig
		want bool
	}{
		{name: "zero", cfg: TLSConfig{}},
		{name: "skip-verify alone", cfg: TLSConfig{SkipVerify: true}},
		{name: "server-name alone", cfg: TLSConfig{ServerName: "x"}},
		{name: "ca alone", cfg: TLSConfig{CAFiles: []string{"a"}}, want: true},
		{name: "cert alone", cfg: TLSConfig{CertFile: "a"}, want: true},
		{name: "key alone", cfg: TLSConfig{KeyFile: "a"}, want: true},
		{name: "cert+key", cfg: TLSConfig{CertFile: "a", KeyFile: "b"}, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, tc.cfg.Enabled())
		})
	}
}

func TestTLSConfigValidate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		cfg     TLSConfig
		wantErr bool
	}{
		{name: "zero"},
		{name: "cert+key ok", cfg: TLSConfig{CertFile: "a", KeyFile: "b"}},
		{name: "cert without key", cfg: TLSConfig{CertFile: "a"}, wantErr: true},
		{name: "key without cert", cfg: TLSConfig{KeyFile: "b"}, wantErr: true},
		{name: "skip-verify+ca rejected", cfg: TLSConfig{SkipVerify: true, CAFiles: []string{"x"}}, wantErr: true},
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

func TestTLSCredentialsDisabledReturnsNil(t *testing.T) {
	t.Parallel()
	creds, err := TLSCredentials(TLSConfig{})
	require.NoError(t, err)
	require.Nil(t, creds)
}

func TestTLSCredentialsLoadsCAAndCert(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	caCert, caKey, caPath := writeCA(t, dir)
	certPath, keyPath := writeLeaf(t, dir, "client", caCert, caKey)

	creds, err := TLSCredentials(TLSConfig{
		CertFile: certPath,
		KeyFile:  keyPath,
		CAFiles:  []string{caPath},
	})
	require.NoError(t, err)
	require.NotNil(t, creds)
}

func TestTLSCredentialsRejectsMissingFiles(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		cfg  TLSConfig
	}{
		{name: "missing cert", cfg: TLSConfig{CertFile: "/no/such/cert", KeyFile: "/no/such/key"}},
		{name: "missing ca", cfg: TLSConfig{CAFiles: []string{"/no/such/ca"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := TLSCredentials(tc.cfg)
			require.Error(t, err)
		})
	}
}

func TestTLSCredentialsRejectsBadCABundle(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	bogus := filepath.Join(dir, "bogus.pem")
	require.NoError(t, os.WriteFile(bogus, []byte("not pem\n"), 0600))

	_, err := TLSCredentials(TLSConfig{CAFiles: []string{bogus}})
	require.Error(t, err)
}

// writeCA mints a self-signed CA and writes it to dir/ca.pem.
func writeCA(t *testing.T, dir string) (*x509.Certificate, *ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	path := filepath.Join(dir, "ca.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600))
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, key, path
}

// writeLeaf mints a leaf cert signed by ca and returns paths to its
// cert and key in dir.
func writeLeaf(t *testing.T, dir, name string, ca *x509.Certificate, caKey *ecdsa.PrivateKey) (certPath, keyPath string) {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &leafKey.PublicKey, caKey)
	require.NoError(t, err)
	certPath = filepath.Join(dir, name+".pem")
	keyPath = filepath.Join(dir, name+".key")
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600))
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600))
	return certPath, keyPath
}
