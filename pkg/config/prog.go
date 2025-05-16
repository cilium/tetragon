// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package config

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/cilium/tetragon/pkg/option"
)

func tryDecompressGz(gzFname, dst string) error {
	gz, err := os.Open(gzFname)
	if err != nil {
		return err
	}
	defer gz.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	zr, err := gzip.NewReader(gz)
	if err != nil {
		return err
	}

	_, err = io.Copy(out, zr)
	if err != nil {
		defer func() {
			// if there was an error, remove the .o file after we close it
			os.Remove(dst)
		}()
	}
	return err
}

// FindProgramFileUnderLocations
func FindProgramFileUnderLocations(name string, locations ...string) (string, error) {
	var checkedPaths []string
	for _, loc := range locations {
		pathname := name
		if len(loc) > 0 {
			pathname = path.Join(loc, filepath.Base(name))
		}

		if _, err := os.Stat(pathname); err == nil {
			return pathname, nil
		}
		checkedPaths = append(checkedPaths, pathname)

		gzFname := pathname + ".gz"
		if _, err := os.Stat(gzFname); err == nil && tryDecompressGz(gzFname, pathname) == nil {
			return pathname, nil
		}
		checkedPaths = append(checkedPaths, gzFname)

	}
	return "", fmt.Errorf("program %q can not be found (checked paths: %s)", name, strings.Join(checkedPaths, ","))
}

// FindProgramFile attempts to find the program file based on its path
func FindProgramFile(name string) (string, error) {
	return FindProgramFileUnderLocations(name, "", option.Config.HubbleLib)
}
