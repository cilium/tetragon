// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package certloader

import (
	"crypto/tls"
	"crypto/x509"
)

// Snapshot exposes the current snapshot for in-package tests.
func (r *Reloader) Snapshot() (*tls.Certificate, *x509.CertPool, bool) {
	s := r.snap.Load()
	if s == nil {
		return nil, nil, false
	}
	return s.cert, s.caPool, s.require
}
