// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"path/filepath"
)

// TestConf is the runtime configuration for a single policy test
type TestConf struct {
	MonitorMode bool
}

// Conf is the runtime configuration for a sequence of policy tests
type Conf struct {
	// Test Binaries directory
	BinsDir string
	// Agent GRPC address
	GrpcAddr string

	// configuration for the current test
	TestConf *TestConf

	// Path to save the generated policy
	DumpPolicyPath string
}

func (c *Conf) TestBinary(s string) string {
	return filepath.Join(c.BinsDir, s)
}
