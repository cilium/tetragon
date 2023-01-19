// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package testutils

import (
	"path/filepath"
	"runtime"
)

// RepoRootPath retrieves the repository root path (useful to find scripts and other files)
func RepoRootPath(fname string) string {
	_, testFname, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(testFname), "..", "..", fname)
}
