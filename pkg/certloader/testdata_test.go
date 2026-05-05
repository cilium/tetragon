// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package certloader

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// TestPKI is a self-contained CA + leaf factory for end-to-end TLS tests.
type TestPKI struct {
	CACert     *x509.Certificate
	CAKey      *ecdsa.PrivateKey
	CACertPEM  []byte
	CACertPath string
}

// NewTestPKI returns a fresh self-signed CA whose certificate is also written
// to dir/ca.pem.
func NewTestPKI(dir string) (*TestPKI, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "tetragon-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, certPEM, 0600); err != nil {
		return nil, err
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &TestPKI{CACert: parsed, CAKey: key, CACertPEM: certPEM, CACertPath: caPath}, nil
}

// IssueOpts customizes a leaf certificate issued by the test CA.
type IssueOpts struct {
	CommonName string
	DNSNames   []string
	IPs        []net.IP
	IsServer   bool
}

// LeafFiles holds the paths to a freshly-issued leaf cert + key on disk.
type LeafFiles struct {
	CertPath string
	KeyPath  string
}

// Issue creates a new ECDSA key + certificate signed by the test CA and writes
// them to dir/<commonName>.{pem,key}.
func (p *TestPKI) Issue(dir string, opts IssueOpts) (*LeafFiles, error) {
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	usage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	extUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	if opts.IsServer {
		extUsage = append(extUsage, x509.ExtKeyUsageServerAuth)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: opts.CommonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     usage,
		ExtKeyUsage:  extUsage,
		DNSNames:     opts.DNSNames,
		IPAddresses:  opts.IPs,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.CACert, &leafKey.PublicKey, p.CAKey)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	certPath := filepath.Join(dir, opts.CommonName+".pem")
	keyPath := filepath.Join(dir, opts.CommonName+".key")
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return nil, err
	}
	return &LeafFiles{CertPath: certPath, KeyPath: keyPath}, nil
}
