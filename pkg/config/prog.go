// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package config

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/cilium/tetragon/pkg/option"
)

// FindProgramFile attempts to find the program file based on its path
func FindProgramFile(name string) (string, error) {
	var checkedPaths []string
	if _, err := os.Stat(name); err == nil {
		return name, nil
	}
	checkedPaths = append(checkedPaths, name)

	name = path.Join(option.Config.HubbleLib, filepath.Base(name))
	if _, err := os.Stat(name); err == nil {
		return name, nil
	}
	checkedPaths = append(checkedPaths, name)
	return "", fmt.Errorf("program %q can not be found (checked paths: %s)", name, strings.Join(checkedPaths, ","))
}
