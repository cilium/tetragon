// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package main

import (
	"os"
	"path/filepath"

	"github.com/cilium/little-vm-helper/pkg/images"
)

var (
	policytestsVmTestProgsDir = "/usr/local/lib/tetragon/tester-progs"
)

func mustCopyTesterProgsCmd(hostDir string, tmpDir string) images.Action {
	// NB: because in general, the basename of hostDir is not the same as the basename of
	// policyTestCmd, we copy the binaries in the temp directory, and do the action from there.
	dstDir := filepath.Join(tmpDir, filepath.Base(policytestsVmTestProgsDir))
	if err := os.Mkdir(dstDir, 0755); err != nil {
		panic(err)
	}

	if err := os.CopyFS(dstDir, os.DirFS(hostDir)); err != nil {
		panic(err)
	}

	return images.Action{Op: &images.CopyInCommand{
		LocalPath: dstDir,
		RemoteDir: filepath.Dir(policytestsVmTestProgsDir),
	}}
}
