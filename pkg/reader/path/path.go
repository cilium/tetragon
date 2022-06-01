// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package path

import (
	"path/filepath"
	"strings"

	"github.com/cilium/tetragon/pkg/api"
	"github.com/cilium/tetragon/pkg/api/processapi"
)

func GetBinaryAbsolutePath(binary string, cwd string) string {
	if filepath.IsAbs(binary) {
		return binary
	}
	return filepath.Join(cwd, binary)
}

func FilePathFlagsToStr(flags uint32) string {
	var retval string

	if (flags & processapi.UnresolvedMountPoints) != 0 {
		retval += "unresolvedMountPoints"
	}
	if (flags & processapi.UnresolvedPathComponents) != 0 {
		if len(retval) > 0 {
			retval += " "
		}
		retval += "unresolvedPathComponents"
	}
	return retval
}

func MarkUnresolvedPathComponents(path string, flags uint32) string {
	retval := path
	if (flags & processapi.UnresolvedMountPoints) != 0 {
		retval = "/[M]" + retval
	}
	if (flags & processapi.UnresolvedPathComponents) != 0 {
		retval = strings.ReplaceAll(retval, "&", "[P]")
	}
	return retval
}

func MarkUnresolvedPathComponentsCwd(path string, flags uint32) string {
	retval := path
	if (flags & api.EventErrorMountPoints) != 0 {
		retval = "/[M]" + retval
	}
	if (flags & api.EventErrorPathComponents) != 0 {
		retval = strings.ReplaceAll(retval, "&", "[P]")
	}
	return retval
}

func SwapPath(path string) string {
	dirs := strings.Split(path, "/")
	for i := len(dirs)/2 - 1; i >= 0; i-- {
		opp := len(dirs) - 1 - i
		dirs[i], dirs[opp] = dirs[opp], dirs[i]
	}
	return strings.Join(dirs, "/")
}
