// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package repo

import (
	"path/filepath"
	"runtime"
)

// RootPath retrieves the repository root path (useful to find scripts and other files)
func RootPath(fname string) string {
	_, testFname, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(testFname), "..", "..", "..", fname)
}
