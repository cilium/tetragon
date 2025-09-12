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
	var checkedPathsErrs []string
	for _, loc := range locations {
		pathname := name
		if len(loc) > 0 {
			pathname = path.Join(loc, filepath.Base(name))
		}

		_, err := os.Stat(pathname)
		if err == nil {
			return pathname, nil
		}
		checkedPathsErrs = append(checkedPathsErrs, fmt.Sprintf("%s: %s", pathname, err))

		gzFname := pathname + ".gz"
		_, err = os.Stat(gzFname)
		if err != nil {
			checkedPathsErrs = append(checkedPathsErrs, fmt.Sprintf("%s: %s", gzFname, err))
			continue
		}

		err = tryDecompressGz(gzFname, pathname)
		if err == nil {
			return pathname, nil
		}
		checkedPathsErrs = append(checkedPathsErrs, fmt.Sprintf("%s: decompressing failed: %s", pathname, err))

	}
	return "", fmt.Errorf("program %q cannot be found (errors: %s)", name, strings.Join(checkedPathsErrs, ";"))
}

// FindProgramFile attempts to find the program file based on its path
func FindProgramFile(name string) (string, error) {
	return FindProgramFileUnderLocations(name, "", option.Config.HubbleLib)
}
