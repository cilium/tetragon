// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kernels

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// directoryExists returns:
//   true,  nil: if a directory with name dir exists
//   false, nil: if a directory with name dir does not exist
//   false, err: if somethign unexpected happened
func directoryExists(dir string) (bool, error) {
	st, err := os.Stat(dir)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err == nil {
		if st.IsDir() {
			return true, nil
		}
		return false, fmt.Errorf("`%s` exists, but is not a directory", dir)
	}

	return false, fmt.Errorf("error accessing `%s`: %w", dir, err)
}

func regularFileExists(fname string) (bool, error) {
	st, err := os.Stat(fname)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err == nil {
		if st.Mode().IsRegular() {
			return true, nil
		}
		return false, fmt.Errorf("`%s` exists, but is not a regular file", fname)
	}

	return false, fmt.Errorf("error accessing `%s`: %w", fname, err)
}

func FindKernel(installDir string) (string, error) {
	prefix := "vmlinuz-"

	dir := filepath.Join(installDir, "boot")
	dentries, err := os.ReadDir(dir)
	if err != nil {
		cwd, _ := os.Getwd()
		return "", fmt.Errorf("failed to reading dir: %v (working dir: %s)", err, cwd)
	}

	kernels := make([]string, 0, 1)
	for _, dentry := range dentries {
		if !dentry.Type().IsRegular() {
			continue
		}

		fname := dentry.Name()
		if !strings.HasPrefix(fname, prefix) {
			continue
		}

		kernels = append(kernels, fname)
	}

	if len(kernels) == 0 {
		return "", fmt.Errorf("no kernel found in '%s'", dir)
	} else if len(kernels) > 1 {
		return "", fmt.Errorf("unhandled case: multiple kernels found in '%s'. TODO: sort them lexicographically and pick the latest", dir)
	}

	return filepath.Join("boot", kernels[0]), nil
}
