// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"path/filepath"
)

// Conf is the runtime configuration
type Conf struct {
	// Test Binaries directory
	BinsDir string
	// Agent GRPC address
	GrpcAddr string

	// Test run configuration
	RunConf *RunConf
}

func (c *Conf) TestBinary(s string) string {
	return filepath.Join(c.BinsDir, s)
}
