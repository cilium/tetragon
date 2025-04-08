// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package testutils

import (
	"io"
	"os"
	"os/exec"
	"path"
	"syscall"
	"testing"
)

func CopyFile(toPath, fromPath string, perm os.FileMode) error {
	from, err := os.Open(fromPath)
	if err != nil {
		return err
	}
	defer from.Close()

	to, err := os.OpenFile(toPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer to.Close()

	_, err = io.Copy(to, from)
	if err != nil {
		syscall.Unlink(toPath)
	}
	return err
}

func CopyFileToTmp(fname string) (string, error) {
	bname := path.Base(fname)
	pattern := bname + ".*"
	outf, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", err
	}
	defer outf.Close()

	inf, err := os.Open(fname)
	if err != nil {
		os.Remove(outf.Name())
		return "", err
	}
	defer inf.Close()

	info, err := inf.Stat()
	if err != nil {
		os.Remove(outf.Name())
		return "", err
	}
	err = os.Chmod(outf.Name(), info.Mode())
	if err != nil {
		os.Remove(outf.Name())
		return "", err
	}

	if _, err := io.Copy(outf, inf); err != nil {
		os.Remove(outf.Name())
		return "", err
	}

	return outf.Name(), nil
}

// CopyExecToTemp copy an executable to temp and return its temporary value.
// The intention here is to allow filtering based on binary for well-known executables
func CopyExecToTemp(t *testing.T, execName string) string {
	path, err := exec.LookPath(execName)
	if err != nil {
		t.Fatalf("failed to find '%s' exec: %v", execName, err)
	}
	tmpPath, err := CopyFileToTmp(path)
	if err != nil {
		t.Fatalf("failed to copy 'sh' exec: %v", err)
	}
	t.Cleanup(func() {
		os.Remove(tmpPath)
	})

	return tmpPath
}
