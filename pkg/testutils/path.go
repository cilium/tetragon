// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package testutils

import (
	"os"
	"path/filepath"
	"runtime"

	"github.com/cilium/tetragon/pkg/tracepoint"
)

// RepoRootPath retrieves the repository root path (useful to find scripts and other files)
func RepoRootPath(fname string) string {
	_, testFname, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(testFname), "..", "..", fname)
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
