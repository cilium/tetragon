// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package testutils

import (
	"fmt"
	"io"
	"os"
	"path"
	"syscall"
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
	pattern := fmt.Sprintf("%s.*", bname)
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
