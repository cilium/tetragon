// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package testutils

import (
	"path/filepath"
	"runtime"
	"strings"
)

// RepoRootPath retrieves the repository root path (useful to find scripts and other files)
func RepoRootPath(fname string) string {
	_, testFname, _, _ := runtime.Caller(0)
	// in the case where this file is vendored (i.e. under vendor directory)
	// we have to skip the path on the right of vendor/
	if index := strings.Index(testFname, "vendor"); index != -1 { // vendor found in path
		return filepath.Join(testFname[0:index], fname)
	}
	return filepath.Join(filepath.Dir(testFname), "..", "..", fname)
}
