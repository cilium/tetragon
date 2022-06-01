// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package path

import (
	"path/filepath"

	"github.com/cilium/tetragon/pkg/api/processapi"
)

func GetBinaryAbsolutePath(binary string, cwd string) string {
	if filepath.IsAbs(binary) {
		return binary
	}
	return filepath.Join(cwd, binary)
}

func FilePathFlagsToStr(flags uint32) string {
	if (flags & processapi.UnresolvedPathComponents) != 0 {
		return "unresolvedPathComponents"
	}
	return ""
}
