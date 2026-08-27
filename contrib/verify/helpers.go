// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package verify

import (
	"fmt"
	"strings"
)

func extractKernelVersion(fileName string) (string, error) {
	if idx := strings.LastIndex(fileName, "_v"); idx != -1 {
		versionPart := strings.TrimSuffix(fileName[idx+2:], ".o")
		if len(versionPart) >= 2 {
			if versionPart[:1] == "1" {
				return "", fmt.Errorf("version 10.x not supported (we will need to disambiguate notation): %s", versionPart)
			}
			return versionPart[:1] + "." + versionPart[1:], nil
		}
	}

	return "", nil
}
