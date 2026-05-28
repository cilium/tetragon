// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package testutils

import (
	"os"
	"path/filepath"

	"github.com/cilium/tetragon/pkg/testutils/repo"
	"github.com/cilium/tetragon/pkg/tracepoint"
)

// RepoRootPath retrieves the repository root path (useful to find scripts and other files)
func RepoRootPath(fname string) string {
	return repo.RootPath(fname)
}

func CheckKernelTracingExists() bool {
	traceFSDir, err := tracepoint.GetTraceFSPath()
	if err != nil {
		return false
	}
	if _, err = os.Stat(filepath.Join(traceFSDir, "events", "syscalls")); os.IsNotExist(err) {
		return false
	}
	return true
}
