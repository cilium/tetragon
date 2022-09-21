// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package testutils

import (
	"path/filepath"
	"runtime"
)

// ContribPath retrieves contrib path (useful to find scripts and other files)
func ContribPath(fname string) string {
	_, testFname, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(testFname), "..", "..", "contrib", fname)
}
