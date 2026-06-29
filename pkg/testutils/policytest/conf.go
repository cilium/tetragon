// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"os"
	"path/filepath"
)

// TestConf is the runtime configuration for a single policy test
type TestConf struct {
	MonitorMode bool
	ParamValues map[string]any
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

	// Map of temporary files generated for this generated policy. Key is
	// unique identifier for the temp file, value is the generated temp
	// filename
	tempFiles map[string]string
}

func (c *Conf) TestBinary(s string) string {
	return filepath.Join(c.BinsDir, s)
}

func (c *Conf) TempFile(key string) (string, error) {
	if c.tempFiles == nil {
		c.tempFiles = make(map[string]string)
	} else if path, ok := c.tempFiles[key]; ok {
		return path, nil // already created — return cached path
	}
	tempFile, err := os.CreateTemp("/var/tmp", "tetragon-testfile-*")
	if err != nil {
		return "", err
	}
	tempFile.Close()
	path := tempFile.Name()
	c.tempFiles[key] = path
	return path, nil
}

func (c *Conf) TempFileMust(key string) string {
	ret, err := c.TempFile(key)
	if err != nil {
		panic(err)
	}
	return ret
}

func (c *Conf) CleanupTempFiles() {
	if c.tempFiles == nil {
		return
	}
	for _, tempFile := range c.tempFiles {
		os.Remove(tempFile)
	}
	c.tempFiles = nil
}
