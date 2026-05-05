// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package common

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/credentials"
)

// Flag keys exposed by the tetra CLI for TLS dialing.
const (
	KeyTLSCertFile   = "tls-cert-file"
	KeyTLSKeyFile    = "tls-key-file"
	KeyTLSCAFiles    = "tls-ca-cert-files"
	KeyTLSServerName = "tls-server-name"
	KeyTLSSkipVerify = "tls-skip-verify"
)

// TLSConfig holds the parsed TLS dial configuration captured from the tetra
// root flags. Subcommands consume this via [TLSCredentials].
type TLSConfig struct {
	CertFile   string
	KeyFile    string
	CAFiles    []string
	ServerName string
	SkipVerify bool
}

// TLS is the package-level holder populated by AddTLSFlags.
var TLS TLSConfig

// Enabled reports whether the dial should switch from plaintext to TLS.
// --tls-skip-verify and --tls-server-name only refine an already-active
// TLS dial; on their own they don't trigger TLS mode.
func (c TLSConfig) Enabled() bool {
	return c.CertFile != "" || c.KeyFile != "" || len(c.CAFiles) > 0
}

// Validate enforces the minimum invariants. --tls-skip-verify with
// --tls-ca-cert-files is rejected because crypto/tls ignores RootCAs when
// InsecureSkipVerify is true, which would silently no-op the CA bundle.
func (c TLSConfig) Validate() error {
	if (c.CertFile == "") != (c.KeyFile == "") {
		return fmt.Errorf("--%s and --%s must be set together", KeyTLSCertFile, KeyTLSKeyFile)
	}
	if c.SkipVerify && len(c.CAFiles) > 0 {
		return fmt.Errorf("--%s makes --%s a no-op (crypto/tls ignores RootCAs when verification is skipped); pick one",
			KeyTLSSkipVerify, KeyTLSCAFiles)
	}
	return nil
}

// AddTLSFlags wires the persistent TLS flags onto cmd. Call exactly once on
// the tetra root command.
func AddTLSFlags(cmd *cobra.Command) {
	flags := cmd.PersistentFlags()
	flags.StringVar(&TLS.CertFile, KeyTLSCertFile, "", "Path to client certificate (PEM) for mTLS")
	flags.StringVar(&TLS.KeyFile, KeyTLSKeyFile, "", "Path to client private key (PEM) for mTLS")
	flags.StringSliceVar(&TLS.CAFiles, KeyTLSCAFiles, nil, "Paths to PEM CA bundles used to verify the server certificate")
	flags.StringVar(&TLS.ServerName, KeyTLSServerName, "", "Override SNI / certificate hostname when dialing the server")
	flags.BoolVar(&TLS.SkipVerify, KeyTLSSkipVerify, false, "Disable server certificate verification (development only)")
}

// TLSCredentials returns gRPC transport credentials, or (nil, nil) when
// cfg.Enabled() is false so callers can fall back to plaintext.
func TLSCredentials(cfg TLSConfig) (credentials.TransportCredentials, error) {
	if !cfg.Enabled() {
		return nil, nil
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         cfg.ServerName,
		InsecureSkipVerify: cfg.SkipVerify, //nolint:gosec // gated by --tls-skip-verify, dev-only
	}
	if cfg.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("loading client cert/key: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	if len(cfg.CAFiles) > 0 {
		pool := x509.NewCertPool()
		for _, p := range cfg.CAFiles {
			pem, err := os.ReadFile(p)
			if err != nil {
				return nil, fmt.Errorf("reading CA bundle %q: %w", p, err)
			}
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("CA bundle %q contained no valid PEM certificates", p)
			}
		}
		tlsCfg.RootCAs = pool
	}
	return credentials.NewTLS(tlsCfg), nil
}
