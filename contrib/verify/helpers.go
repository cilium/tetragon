// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package verify

import (
	"strings"
)

func extractKernelVersion(fileName string) string {
	if idx := strings.LastIndex(fileName, "_v"); idx != -1 {
		versionPart := strings.TrimSuffix(fileName[idx+2:], ".o")
		if len(versionPart) >= 2 {
			if versionPart[:1] == "1" {
				panic("version 10.x not supported (we will need to disambiguate notation): " + versionPart)
			}
			return versionPart[:1] + "." + versionPart[1:]
		}
	}

	return ""
}
