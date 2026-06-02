// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

// Package grpctls_test verifies the agent's TCP gRPC listener enforces mTLS:
// a valid client cert succeeds, plaintext and anonymous TLS clients are
// rejected. Test logic lives in tests/e2e/helpers/grpctls.
package grpctls_test

import (
	"testing"

	"github.com/cilium/tetragon/tests/e2e/helpers/grpctls"
	tetragoninstall "github.com/cilium/tetragon/tests/e2e/install/tetragon"
	"github.com/cilium/tetragon/tests/e2e/runners"
)

var runner *runners.Runner

// TestMain installs Tetragon with mTLS via the helm method. The runner's
// default plaintext auto port-forward is skipped because it would fail the
// handshake against a TLS-required listener.
func TestMain(m *testing.M) {
	runner = runners.NewRunner().
		NoPortForward().
		WithInstallTetragon(tetragoninstall.WithHelmOptions(grpctls.HelmOptions())).
		Init()
	runner.Run(m)
}

func TestMTLSHandshake(t *testing.T) {
	runner.Test(t, grpctls.HandshakeFeature(runner))
}

func TestMTLSRejectsPlaintext(t *testing.T) {
	runner.Test(t, grpctls.RejectsPlaintextFeature(runner))
}

func TestMTLSRejectsAnonymousTLS(t *testing.T) {
	runner.Test(t, grpctls.RejectsAnonymousTLSFeature(runner))
}
