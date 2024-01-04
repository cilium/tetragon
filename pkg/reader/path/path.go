// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package path

import (
	"github.com/cilium/tetragon/pkg/api/processapi"
)

func FilePathFlagsToStr(flags uint32) string {
	if (flags & processapi.UnresolvedPathComponents) != 0 {
		return "unresolvedPathComponents"
	}
	return ""
}
