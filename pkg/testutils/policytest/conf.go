// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"fmt"
	"path/filepath"
	"strings"
)

type ParamVals map[string]any

func (pvs ParamVals) String() string {
	parts := make([]string, 0, len(pvs))
	for k, v := range pvs {
		parts = append(parts, fmt.Sprintf("%s=%v", k, v))
	}
	return strings.Join(parts, " ")
}

func newParamVals() ParamVals {
	return ParamVals(make(map[string]any))
}

// TestConf is the runtime configuration for a single policy test
type TestConf struct {
	MonitorMode bool
	ParamValues ParamVals
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
